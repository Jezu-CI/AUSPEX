#!/usr/bin/env python3
"""Raccordement du capteur au central par un code d'invitation.

    rejoindre.py HOTE[:PORT] CODE --cle /etc/auspex-capteur/cle.pub --conf /etc/auspex-capteur

1. vérifie la clé d'hôte du central contre le début d'empreinte contenu dans le
   code (un faux central est refusé avant tout échange) ;
2. dérive du code la clé d'invitation (scrypt puis Ed25519, comme le central) ;
3. envoie la clé publique du capteur par la commande d'inscription, la seule que
   cette clé d'invitation autorise ;
4. retient l'adresse et l'empreinte complète du central (central.env), lues
   ensuite par « live » et « envoyer ».

Python standard et OpenSSH uniquement (image du capteur) : Ed25519 d'après la
référence de la RFC 8032, fichier de clé au format OpenSSH.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
import subprocess
import sys
import tempfile

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
SECRET_CARS, EMPREINTE_CARS = 12, 16
SEL = b"auspex-invitation-v1"


class Erreur(Exception):
    pass


# --- Code (identique à auspex.invitation) --------------------------------------

def normaliser(code: str) -> str:
    s = "".join(c for c in code.upper() if c not in " -_\t")
    s = s.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))
    if len(s) != SECRET_CARS + EMPREINTE_CARS or any(c not in ALPHABET for c in s):
        raise Erreur("code d'invitation invalide (28 caractères attendus, tirets facultatifs)")
    return s


def b32(data: bytes, cars: int) -> str:
    n = int.from_bytes(data, "big") >> max(0, len(data) * 8 - cars * 5)
    return "".join(ALPHABET[(n >> (5 * (cars - 1 - i))) & 31] for i in range(cars))


def graine(code: str) -> bytes:
    return hashlib.scrypt(normaliser(code)[:SECRET_CARS].encode(), salt=SEL, n=2 ** 14, r=8, p=1, dklen=32)


# --- Ed25519 (RFC 8032, section 5.1) : clé publique depuis la graine -----------

_P = 2 ** 255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_GY = 4 * pow(5, _P - 2, _P) % _P


def _recover_x(y: int, sign: int) -> int:
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x & 1 != sign:
        x = _P - x
    return x


_G = (_recover_x(_GY, 0), _GY, 1, _recover_x(_GY, 0) * _GY % _P)


def _add(a, b):
    A = (a[1] - a[0]) * (b[1] - b[0]) % _P
    B = (a[1] + a[0]) * (b[1] + b[0]) % _P
    C = 2 * a[3] * b[3] * _D % _P
    D = 2 * a[2] * b[2] % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s: int, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def cle_publique_ed25519(seed: bytes) -> bytes:
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    x, y, z, _ = _mul(a, _G)
    zi = pow(z, _P - 2, _P)
    x, y = x * zi % _P, y * zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


# --- Fichiers de clé OpenSSH --------------------------------------------------

def _chaine(b: bytes) -> bytes:
    return len(b).to_bytes(4, "big") + b


def blob_public(pub: bytes) -> bytes:
    return _chaine(b"ssh-ed25519") + _chaine(pub)


def cle_privee_openssh(seed: bytes, commentaire: str = "auspex-invitation") -> str:
    pub = cle_publique_ed25519(seed)
    check = os.urandom(4)
    priv = (check + check + _chaine(b"ssh-ed25519") + _chaine(pub) + _chaine(seed + pub)
            + _chaine(commentaire.encode()))
    priv += bytes(range(1, 1 + (-len(priv) % 8)))
    corps = (b"openssh-key-v1\0" + _chaine(b"none") + _chaine(b"none") + _chaine(b"")
             + (1).to_bytes(4, "big") + _chaine(blob_public(pub)) + _chaine(priv))
    b64 = base64.b64encode(corps).decode()
    return ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
            + "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
            + "\n-----END OPENSSH PRIVATE KEY-----\n")


def empreinte(blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# --- Raccordement -------------------------------------------------------------

def hote_port(central: str) -> tuple[str, int]:
    if central.startswith("["):
        hote, _, reste = central[1:].partition("]")
        return hote, int(reste[1:]) if reste.startswith(":") else 2222
    if central.count(":") == 1:
        hote, port = central.split(":")
        return hote, int(port)
    return central, 2222


def verifier_central(hote: str, port: int, code: str, known: str) -> str:
    """Clé d'hôte du central, vérifiée contre le code ; écrit known_hosts ; renvoie l'empreinte."""
    attendu = normaliser(code)[SECRET_CARS:]
    r = subprocess.run(["ssh-keyscan", "-T", "10", "-t", "ed25519", "-p", str(port), hote],
                       capture_output=True, text=True, timeout=30)
    lignes = [li for li in r.stdout.splitlines() if " ssh-ed25519 " in li and not li.startswith("#")]
    if not lignes:
        raise Erreur(f"central injoignable sur {hote}:{port} (réception des capteurs)")
    blob = base64.b64decode(lignes[0].split()[2])
    if b32(hashlib.sha256(blob).digest(), EMPREINTE_CARS) != attendu:
        raise Erreur(f"la clé du central {hote}:{port} ne correspond pas au code : faux central, "
                     "ou code d'un autre central. Rien n'a été envoyé.")
    with open(known, "w", encoding="utf-8") as fh:
        fh.write(lignes[0] + "\n")
    return empreinte(blob)


def rejoindre(central: str, code: str, cle_pub: str, conf: str) -> str:
    hote, port = hote_port(central)
    with open(cle_pub, encoding="utf-8") as fh:
        cle = fh.read().strip()
    with tempfile.TemporaryDirectory() as tmp:
        known = os.path.join(tmp, "known_hosts")
        fp = verifier_central(hote, port, code, known)
        ident = os.path.join(tmp, "invitation")
        fd = os.open(ident, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(cle_privee_openssh(graine(code)))
        cible = f"capteur@[{hote}]" if ":" in hote else f"capteur@{hote}"
        r = subprocess.run(["ssh", "-i", ident, "-p", str(port), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known}",
                            "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ConnectTimeout=15", "-o", "LogLevel=ERROR",
                            cible], input=cle + "\n", capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            detail = (r.stderr or r.stdout).strip().splitlines()
            raise Erreur("le central a refusé le code (expiré, déjà utilisé, ou capteur non autorisé depuis "
                         f"cette adresse) : {detail[-1] if detail else 'refus'}")
    os.makedirs(conf, exist_ok=True)
    adresse = f"[{hote}]:{port}" if ":" in hote else f"{hote}:{port}"
    chemin = os.path.join(conf, "central.env")
    with open(chemin + ".tmp", "w", encoding="utf-8") as fh:
        fh.write(f"AUSPEX_CENTRAL={adresse}\nAUSPEX_CENTRAL_EMPREINTE={fp}\n")
    os.replace(chemin + ".tmp", chemin)
    return fp


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Raccorder ce capteur au central Auspex par un code d'invitation.")
    p.add_argument("central", help="adresse du central, port facultatif (2222 par défaut)")
    p.add_argument("code", help="code affiché par « auspex capteur inviter » sur le central")
    p.add_argument("--cle", default="/etc/auspex-capteur/cle.pub", help="clé publique d'envoi du capteur")
    p.add_argument("--conf", default="/etc/auspex-capteur", help="dossier de configuration du capteur")
    a = p.parse_args(argv)
    try:
        fp = rejoindre(a.central, a.code, a.cle, a.conf)
    except (Erreur, OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"Raccordement impossible : {exc}", file=sys.stderr)
        return 1
    print(f"Central vérifié ({fp}) et inscription envoyée.\n"
          "Le central enregistre ce capteur à son prochain cycle (5 minutes au plus) ; démarrer\n"
          "l'écoute (« live ») : l'adresse et l'empreinte du central sont retenues.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
