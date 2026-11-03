"""Restriction des connexions par IP source (« trusted hosts »).

Module sans dépendance à NetBox : le plugin NetBox l'appelle avant toute
action, pour chaque requête authentifiée (session de l'interface ou jeton
d'API). Toute la logique de décision est ici, et testée.

Règles, dans l'ordre :

1. IP réelle du client : celle de la connexion. L'en-tête X-Forwarded-For
   n'est lu que si la connexion vient d'un proxy déclaré
   (access.trusted_proxies) ; sinon il est ignoré, car il se falsifie.
2. Comptes de service (Librarian) : acceptés uniquement depuis le réseau
   Docker interne du central. Un jeton volé est inutilisable ailleurs.
3. Brise-glace et administrateur local de NetBox : acceptés depuis la
   machine du central (qui y a accès peut de toute façon lire .env), depuis
   le réseau interne (scripts d'installation et de mise à jour) ; le
   brise-glace l'est aussi depuis ses adresses déclarées.
4. Autres utilisateurs : leurs règles (par utilisateur ou par groupe) ; sans
   règle, la politique par défaut (refus, sauf allow_if_unlisted).
5. Configuration absente ou invalide : verrouillage, seuls l'administrateur
   local (depuis la machine du central ou le réseau interne) et les comptes de
   service (réseau interne) restent acceptés.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable

from .config import AccessConfig

SERVICE_ACCOUNTS = ("Librarian",)
LOCAL_ADMINS = ("admin",)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    client_ip: str
    reason: str


def _ip(value: str | None):
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped:  # ::ffff:10.0.0.1
        return addr.ipv4_mapped
    return addr


def _in(addr, nets: Iterable) -> bool:
    return addr is not None and any(addr.version == n.version and addr in n for n in nets)


class AccessPolicy:
    def __init__(self, access: AccessConfig | None, internal_subnet: str | None = None,
                 service_accounts: Iterable[str] = SERVICE_ACCOUNTS,
                 local_admins: Iterable[str] = LOCAL_ADMINS, front_proxy: str | None = None):
        """`access` à None : configuration absente ou invalide → verrouillage.

        `local_admins` : compte(s) administrateur local de NetBox, utilisé par
        les scripts d'installation et de mise à jour. Toujours accepté depuis
        la machine du central et le réseau interne, même si auspex.yaml ne
        déclare pas de brise-glace : sinon une configuration incomplète
        bloquerait les mises à jour.
        """
        self.access = access
        # Front HTTPS d'Auspex (adresse fixe sur le réseau interne) : toujours un
        # proxy de confiance, il écrit lui-même X-Forwarded-For (jamais recopié du client).
        self.front = _ip(front_proxy) if front_proxy else None
        self.service_accounts = set(service_accounts)
        self.local_admins = set(local_admins)
        self.internal = ipaddress.ip_network(internal_subnet, strict=False) if internal_subnet else None
        # La passerelle du réseau interne est la machine du central elle-même :
        # c'est par elle qu'arrivent les connexions locales (tunnel SSH,
        # reverse proxy installé sur la machine).
        self.local = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
        if self.internal is not None:
            self.local.add(next(self.internal.hosts()))

    def client_ip(self, remote_addr: str | None, forwarded_for: str | None) -> tuple:
        """(IP du client, la requête a-t-elle traversé un proxy de confiance ?)"""
        peer = _ip(remote_addr)
        proxies = tuple(self.access.trusted_proxies) if self.access else ()
        if self.front is not None:
            proxies += (ipaddress.ip_network(self.front),)
        if peer is None or not forwarded_for or not _in(peer, proxies):
            return peer, False
        # On remonte la chaîne depuis la droite : la dernière adresse qui
        # n'est pas un proxy de confiance est le client. Les entrées plus à
        # gauche ont pu être écrites par le client lui-même : ignorées.
        addr = None
        for entry in reversed(forwarded_for.split(",")):
            addr = _ip(entry)
            if addr is None:
                return peer, False  # chaîne illisible : on ne lui fait pas confiance
            if not _in(addr, proxies):
                return addr, True
        # Toute la chaîne est faite de proxys de confiance : le client est le premier
        # d'entre eux (ex. un poste sur la machine du central, via la passerelle déclarée,
        # puis le front HTTPS). Relevé en CI : on renvoyait l'adresse du front.
        return (addr, True) if addr is not None else (peer, False)

    def decide(self, username: str | None, groups: Iterable[str] = (), remote_addr: str | None = None,
               forwarded_for: str | None = None) -> Decision:
        if not username:
            return Decision(True, str(remote_addr), "requête anonyme : rien à restreindre")
        client, forwarded = self.client_ip(remote_addr, forwarded_for)
        shown = str(client) if client is not None else "inconnue"
        if client is None:
            return Decision(False, shown, "adresse source illisible")
        peer = _ip(remote_addr)
        is_local = not forwarded and peer in self.local
        is_internal = (not forwarded and self.internal is not None and peer not in self.local
                       and _in(peer, [self.internal]))

        if self.access is None:
            # Verrouillage : seuls l'administrateur local et les comptes de
            # service, depuis la machine du central ou son réseau interne.
            # Surtout pas « tout utilisateur depuis la machine » : un reverse
            # proxy installé sur la machine fait arriver TOUTES les connexions
            # par elle, une configuration cassée ouvrirait alors tout.
            if username in self.service_accounts:
                ok = is_internal
            else:
                ok = username in self.local_admins and (is_local or is_internal)
            return Decision(ok, shown, "verrouillage : administrateur local" if ok else
                            "configuration d'accès illisible : verrouillage, seul l'administrateur "
                            "local est accepté depuis la machine du central")

        if username in self.service_accounts:
            return Decision(is_internal, shown, "compte de service : réseau interne du central"
                            if is_internal else "compte de service hors du réseau interne du central")

        if username == self.access.break_glass_user or username in self.local_admins:
            declared = self.access.break_glass_allow if username == self.access.break_glass_user else ()
            ok = is_local or is_internal or _in(client, declared)
            return Decision(ok, shown, "brise-glace : adresse autorisée" if ok
                            else "brise-glace : adresse non autorisée")

        groups = set(groups)
        nets = [n for r in self.access.trusted_hosts
                if (r.subject_kind == "user" and r.subject == username)
                or (r.subject_kind == "group" and r.subject in groups)
                for n in r.allow]
        if nets:
            ok = _in(client, nets)
            return Decision(ok, shown, "adresse autorisée pour cet utilisateur" if ok
                            else "adresse non autorisée pour cet utilisateur")
        ok = self.access.default == "allow_if_unlisted"
        return Decision(ok, shown, "aucune règle : politique par défaut " +
                        ("permissive" if ok else "restrictive (deny_if_unlisted)"))
