#!/usr/bin/env python3
"""Lance une cible de fuzzing.

  python fuzz/fuzz.py CIBLE [SECONDES]        (défaut : 60 s)
  python fuzz/fuzz.py --toutes [SECONDES]     (chaque cible, l'une après l'autre)

Avec Atheris installé (pip install atheris, Python 3.11) : fuzzing guidé par la
couverture de code. Sans Atheris : mutations aléatoires du corpus (moins efficace,
mais utilisable partout). Un plantage affiche l'entrée fautive et l'enregistre
dans fuzz/plantages/.
"""
from __future__ import annotations

import random
import sys
import time
import traceback
from pathlib import Path

# Le code du dépôt d'abord (et non une version installée ailleurs), puis les cibles
sys.path[:0] = [str(Path(__file__).resolve().parent.parent / "src"), str(Path(__file__).resolve().parent)]
import cibles  # noqa: E402

ICI = Path(__file__).resolve().parent


def corpus(cible: str) -> list[bytes]:
    d = ICI / "corpus" / cible
    return [p.read_bytes() for p in sorted(d.glob("*"))] if d.is_dir() else [b""]


def muter(rng: random.Random, data: bytes, graines: list[bytes]) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 8)):
        op = rng.randrange(7)
        pos = rng.randrange(len(b) + 1)
        if op == 0 and b:                              # inverser un bit
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1:                                  # octet quelconque
            b[pos:pos] = bytes([rng.randrange(256)])
        elif op == 2 and b:                            # supprimer une tranche
            del b[pos:pos + rng.randint(1, 16)]
        elif op == 3:                                  # valeurs piégeuses
            b[pos:pos] = rng.choice([b"\x00", b"\xff\xfe", b"\\x", b"\\", b"inf", b"nan", b"-1",
                                     b"99999999999999999999", b"\n", b"\t", b"#separator",
                                     b"#fields", b"{", b"}", b"\"", b";", b",", b"-", b"..",
                                     b"\xc3\xa9", b"\xe2\x80\xae", b"*" * 300])
        elif op == 4 and b:                            # dupliquer une tranche
            s = b[pos:pos + rng.randint(1, 64)]
            b[pos:pos] = s
        elif op == 5:                                  # greffer une autre graine
            g = rng.choice(graines)
            s = rng.randrange(len(g) + 1)
            b[pos:pos] = g[s:s + 64]
        else:                                          # couper
            del b[pos:]
    return bytes(b)


def sans_atheris(nom: str, secondes: float, graine: int = 0) -> int:
    f = cibles.CIBLES[nom]
    graines = corpus(nom)
    rng = random.Random(graine)
    fin, n = time.monotonic() + secondes, 0
    while time.monotonic() < fin:
        data = muter(rng, rng.choice(graines), graines) if rng.random() < 0.9 else rng.randbytes(rng.randrange(256))
        n += 1
        try:
            f(data)
        except Exception:
            dossier = ICI / "plantages"
            dossier.mkdir(exist_ok=True)
            fichier = dossier / f"{nom}-{n}.bin"
            fichier.write_bytes(data)
            print(f"PLANTAGE {nom} après {n} essais : {data[:200]!r}\n  enregistré dans {fichier}")
            traceback.print_exc()
            return 1
    print(f"{nom} : {n} essais en {secondes:.0f} s, aucun plantage")
    return 0


def avec_atheris(nom: str, secondes: float) -> int:
    import atheris  # fuzzing guidé par la couverture (détecté par OpenSSF Scorecard)
    f = cibles.CIBLES[nom]
    dossier = ICI / "corpus" / nom
    atheris.Setup([sys.argv[0], f"-max_total_time={int(secondes)}", "-rss_limit_mb=2048",
                   f"-artifact_prefix={ICI / 'plantages'}/{nom}-", str(dossier)],
                  lambda data: f(data))
    (ICI / "plantages").mkdir(exist_ok=True)
    atheris.Fuzz()
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    noms = list(cibles.CIBLES) if argv[0] == "--toutes" else [argv[0]]
    secondes = float(argv[1]) if len(argv) > 1 else 60
    try:
        import atheris  # noqa: F401
        moteur = avec_atheris
    except ImportError:
        moteur = sans_atheris
    code = 0
    for nom in noms:
        code |= moteur(nom, secondes)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
