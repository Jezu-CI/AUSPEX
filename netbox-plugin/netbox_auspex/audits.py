"""Page « Exports d'audit » : exports signés produits par le service Auspex.

NetBox lit l'index écrit par le service (<tableau>/audits/index.json) et sert
les archives qui y figurent ; il n'a ni la clé de signature ni la bibliothèque
de signature. Mêmes droits que les autres pages Auspex (lecture de
l'inventaire) ; chaque téléchargement est journalisé.
"""

from __future__ import annotations

import json
import logging
import os
import re

from django.http import FileResponse, Http404
from django.shortcuts import render

from .dashboard import _guard, _SnapshotCache
from .mfa import _client_ip

logger = logging.getLogger("netbox_auspex")
ARCHIVE = re.compile(r"^auspex-audit-[a-z0-9]{2,16}-\d{8}T\d{4}Z(-\d{1,4})?\.zip$")
STATUS = {"ecarts": ("avec écarts", "red"), "aucun_ecart": ("sans écart", "green"),
          "preuve": ("preuve", "blue"), "non_evalue": ("non évalué", "secondary")}

_index = _SnapshotCache(os.path.join("audits", "index.json"))


def _directory() -> str:
    from .middleware import get_plugin_config
    return os.path.join(os.path.dirname(get_plugin_config("netbox_auspex", "dashboard_path")), "audits")


def _decorate(e: dict) -> dict:
    synth = e.get("synthese") or {}
    counts = {}
    for st in synth.values():
        counts[st] = counts.get(st, 0) + 1
    return {**e, "badges": [(STATUS[k][0], STATUS[k][1], counts[k]) for k in STATUS if counts.get(k)],
            "controls": [(ref, *STATUS.get(st, (st, "secondary"))) for ref, st in synth.items()],
            "size_kb": max(1, round((e.get("taille") or 0) / 1024)),
            "generated": str(e.get("genere_le") or "")[:16].replace("T", " "),
            "period_start": str((e.get("periode") or {}).get("debut", ""))[:10],
            "period_end": str((e.get("periode") or {}).get("fin", ""))[:10]}


def audits_view(request):
    redirect_ = _guard(request)
    if redirect_:
        return redirect_
    index = _index.get() or {}
    exports = [_decorate(e) for e in index.get("exports", []) if ARCHIVE.match(str(e.get("fichier", "")))]
    return render(request, "netbox_auspex/audits.html", {"index": index, "exports": exports,
                                                          "fingerprint": index.get("cle")})


def audit_download_view(request, name: str):
    redirect_ = _guard(request)
    if redirect_:
        return redirect_
    index = _index.get() or {}
    listed = {e.get("fichier") for e in index.get("exports", [])}
    if not ARCHIVE.match(name) or name not in listed:
        raise Http404("export inconnu")
    folder = os.path.realpath(_directory())
    path = os.path.realpath(os.path.join(folder, name))
    if os.path.dirname(path) != folder or not os.path.isfile(path):
        raise Http404("export introuvable")
    logger.warning(json.dumps({"event": "auspex_audit_download", "user": request.user.username,
                               "remote_addr": _client_ip(request), "file": name}, ensure_ascii=False))
    return FileResponse(open(path, "rb"), as_attachment=True, filename=name, content_type="application/zip")
