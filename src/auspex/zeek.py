"""Lecture des logs Zeek (JSON ou TSV natif, compressés gzip ou non).

On ne garde jamais les connexions une par une : elles sont agrégées en flux
(source, destination, protocole, port) avec compteurs et dates de première et
dernière vue. C'est ce qui permet de tenir sur un petit central.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

# États TCP Zeek où une session a réellement été établie. Les tentatives
# rejetées (REJ, S0...) sont comptées à part : elles prouvent qu'un filtrage
# fonctionne, pas qu'un flux existe.
TCP_ESTABLISHED = {"SF", "S1", "S2", "S3", "RSTO", "RSTR"}


def _open_bin(path: Path):
    if path.name.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def _complete_lines(path: Path) -> Iterator[tuple[int, bytes]]:
    """(position de début, ligne) pour chaque ligne COMPLÈTE du fichier.

    Une dernière ligne sans retour à la ligne est en cours d'écriture par Zeek :
    elle est ignorée et sera lue au passage suivant. Une archive gzip tronquée
    (en cours d'écriture) est lue jusqu'au dernier octet décompressible.
    """
    pos = 0
    with _open_bin(path) as fh:
        try:
            for raw in fh:
                if not raw.endswith(b"\n"):
                    return
                yield pos, raw
                pos += len(raw)
        except (EOFError, OSError):
            return


def file_identity(path: str | Path) -> str | None:
    """Empreinte stable d'un fichier de log : en-tête + premier enregistrement.

    Elle ne change ni quand le fichier grossit, ni quand Zeek le renomme à la
    rotation, ni quand il est copié vers le central. None tant que le fichier
    ne contient aucun enregistrement complet.
    """
    h = hashlib.sha256()
    for _, raw in _complete_lines(Path(path)):
        h.update(raw)
        if raw.strip() and not raw.startswith(b"#"):
            return h.hexdigest()
    return None


def read_log(path: str | Path, start: int = 0, progress: dict | None = None) -> Iterator[dict]:
    """Itère sur les enregistrements d'un log Zeek, quel que soit le format.

    `start` : nombre d'octets (décompressés) déjà traités ; les enregistrements
    situés avant ne sont pas renvoyés. `progress["end"]` reçoit la position de
    fin de la dernière ligne complète lue.
    """
    path = Path(path)
    fields: list[str] | None = None
    sep = "\t"
    unset, empty = "-", "(empty)"
    end = start
    for pos, raw in _complete_lines(path):
        end = max(end, pos + len(raw))
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line:
            continue
        if line.startswith("#"):
            # Les en-têtes TSV sont toujours relus : ils décrivent les colonnes.
            if line.startswith("#separator"):
                sep = line.split(" ", 1)[1].encode().decode("unicode_escape")
            elif line.startswith("#fields"):
                fields = line.split(sep)[1:]
            elif line.startswith("#unset_field"):
                unset = line.split(sep)[1]
            elif line.startswith("#empty_field"):
                empty = line.split(sep)[1]
            continue
        if pos < start:
            continue
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                pass
            continue
        if fields is None:
            continue
        rec = {}
        for k, v in zip(fields, line.split(sep)):
            if v == unset:
                continue
            rec[k] = "" if v == empty else v
        yield rec
    if progress is not None:
        progress["end"] = end


def log_kind(path: Path) -> str:
    """'conn.2026-10-30.log.gz' → 'conn'."""
    return path.name.split(".", 1)[0]


def list_log_files(directory: str | Path) -> list[Path]:
    directory = Path(directory)
    # Liens symboliques ignorés : un capteur ne doit pas pouvoir faire lire au
    # central un fichier hors de son dossier (ou le dossier d'un autre capteur).
    # rglob ne descend pas dans les répertoires qui sont des liens.
    # auspex-etat.json : état de l'appliance (version d'analyse), pas un log Zeek.
    return sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()
                  and p.name != "auspex-etat.json"
                  and (p.suffix in {".log", ".json"} or p.name.endswith(".log.gz")))


def iter_logs(directory: str | Path, ledger=None) -> Iterator[tuple[str, dict]]:
    """Parcourt un répertoire de logs Zeek et renvoie (type, enregistrement).

    Avec un registre d'ingestion (`ledger`), seuls les enregistrements jamais
    lus sont renvoyés ; le registre est mis à jour en mémoire, à l'appelant de
    l'enregistrer une fois l'analyse terminée.
    """
    for p in list_log_files(directory):
        kind = log_kind(p)
        if ledger is None:
            for rec in read_log(p):
                yield kind, rec
            continue
        ident = file_identity(p)
        if ident is None:
            continue
        start = ledger.offset(ident)
        progress: dict = {}
        n = 0
        for rec in read_log(p, start, progress):
            n += 1
            yield kind, rec
        ledger.record(ident, p, progress.get("end", start), n)


def ts_of(rec: dict) -> datetime | None:
    ts = rec.get("ts")
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except (TypeError, ValueError):
        try:
            return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return None


def _int(v) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


@dataclass
class Flow:
    src: str
    dst: str
    proto: str
    port: int | None
    first_seen: datetime
    last_seen: datetime
    count: int = 0
    bytes: int = 0
    attempts_rejected: int = 0
    services: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple:
        return (self.src, self.dst, self.proto, self.port)

    @property
    def established(self) -> bool:
        return self.count > 0

    def to_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst, "proto": self.proto, "port": self.port,
            "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
            "count": self.count, "bytes": self.bytes, "attempts_rejected": self.attempts_rejected,
            "services": sorted(self.services),
        }


def aggregate_conn(records: Iterator[dict]) -> dict[tuple, Flow]:
    """Agrège des enregistrements conn.log en flux."""
    flows: dict[tuple, Flow] = {}
    for rec in records:
        src, dst = rec.get("id.orig_h"), rec.get("id.resp_h")
        proto = (rec.get("proto") or "").lower()
        ts = ts_of(rec)
        if not (src and dst and proto and ts):
            continue
        port = _int(rec.get("id.resp_p"))
        if proto == "icmp":
            port = None
        key = (src, dst, proto, port)
        f = flows.get(key)
        if f is None:
            f = flows[key] = Flow(src, dst, proto, port, ts, ts)
        f.first_seen = min(f.first_seen, ts)
        f.last_seen = max(f.last_seen, ts)
        state = rec.get("conn_state", "")
        if proto == "tcp" and state and state not in TCP_ESTABLISHED:
            f.attempts_rejected += 1
            continue
        f.count += 1
        f.bytes += (_int(rec.get("orig_bytes")) or 0) + (_int(rec.get("resp_bytes")) or 0)
        svc = rec.get("service")
        if svc:
            f.services.update(s for s in str(svc).split(",") if s)
    return flows
