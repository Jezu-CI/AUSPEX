"""Résolution IP → zone par correspondance du préfixe le plus long."""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from .config import Zone

UNKNOWN_ZONE = "(inconnue)"


class ZoneMap:
    def __init__(self, zones: list[Zone]):
        self.zones = {z.name: z for z in zones}
        # Préfixes triés du plus spécifique au moins spécifique.
        self._entries = sorted(
            ((p, z) for z in zones for p in z.prefixes),
            key=lambda e: e[0].prefixlen,
            reverse=True,
        )
        self.lookup = lru_cache(maxsize=65536)(self._lookup)

    def _lookup(self, ip: str) -> Zone | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for prefix, zone in self._entries:
            if addr.version == prefix.version and addr in prefix:
                return zone
        return None

    def name_of(self, ip: str) -> str:
        z = self.lookup(ip)
        return z.name if z else UNKNOWN_ZONE

    def class_of(self, ip: str) -> str | None:
        z = self.lookup(ip)
        return z.zclass if z else None
