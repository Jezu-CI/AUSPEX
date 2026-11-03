"""Faux NetBox en mémoire, pour tester la synchronisation sans serveur réel.

Il reproduit les comportements qui comptent : authentification par jeton,
pagination (pages volontairement petites), création et mise à jour en lot,
refus des champs personnalisés inconnus, objets attachés aux interfaces.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE = 2  # pages minuscules : force le suivi des liens « next »


class FakeNetBox:
    def __init__(self, token="secret", version="4.4.1", ignore_token_key=False):
        self.token = token
        # Simule un NetBox qui ignore la clé fournie et en génère une autre
        self.ignore_token_key = ignore_token_key
        self.version = version
        self.data = {
            "/api/extras/custom-fields/": [], "/api/extras/tags/": [],
            "/api/ipam/ip-addresses/": [], "/api/dcim/devices/": [],
            "/api/virtualization/virtual-machines/": [],
            "/api/users/users/": [], "/api/users/permissions/": [], "/api/users/tokens/": [],
        }
        self.next_id = 1000
        self.requests = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=None):
                raw = json.dumps(body).encode() if body is not None else b""
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _auth(self):
                """Jeton administrateur, ou jeton créé par l'API (non administrateur).

                Un jeton non administrateur se voit refuser l'administration
                (utilisateurs, permissions, jetons) et la création de champs :
                c'est ce qui permet de vérifier l'identité du jeton de Librarian.
                """
                header = self.headers.get("Authorization") or ""
                key = header.split(" ", 1)[1] if " " in header else ""
                if key == fake.token:
                    return True
                if key not in {t["key"] for t in fake.data["/api/users/tokens/"]}:
                    self._send(403, {"detail": "Invalid token"})
                    return False
                path = urlparse(self.path).path
                if path.startswith("/api/users/") or (self.command != "GET" and path.startswith("/api/extras/")):
                    self._send(403, {"detail": "You do not have permission to perform this action."})
                    return False
                return True

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def do_GET(self):
                if not self._auth():
                    return
                u = urlparse(self.path)
                q = {k: v[0] for k, v in parse_qs(u.query).items()}
                fake.requests.append(("GET", u.path))
                if u.path == "/api/status/":
                    return self._send(200, {"netbox-version": fake.version})
                items = fake.data.get(u.path)
                if items is None:
                    return self._send(404, {"detail": "Not found"})
                for field in ("slug", "username", "name"):
                    if field in q:
                        items = [i for i in items if i.get(field) == q[field]]
                offset = int(q.get("offset", 0))
                page = items[offset:offset + PAGE]
                nxt = None
                if offset + PAGE < len(items):
                    nxt = f"http://{self.headers['Host']}{u.path}?limit={PAGE}&offset={offset + PAGE}"
                return self._send(200, {"count": len(items), "next": nxt, "previous": None, "results": page})

            def do_POST(self):
                if not self._auth():
                    return
                path = urlparse(self.path).path
                fake.requests.append(("POST", path))
                body = self._body()
                items = body if isinstance(body, list) else [body]
                if path == "/api/extras/custom-fields/":
                    for b in items:
                        if "object_types" not in b:
                            return self._send(400, {"object_types": ["Ce champ est obligatoire."]})
                if path == "/api/ipam/ip-addresses/":
                    err = fake._check_cf(items)
                    if err:
                        return self._send(400, err)
                created = []
                for b in items:
                    fake.next_id += 1
                    obj = {**b, "id": fake.next_id}
                    if path == "/api/ipam/ip-addresses/":
                        obj["tags"] = [{"slug": t["slug"], "name": t["slug"]} for t in b.get("tags", [])]
                        obj["status"] = {"value": b.get("status", "active")}
                    if path == "/api/users/tokens/" and fake.ignore_token_key:
                        obj["key"] = "f" * 40
                    if path == "/api/users/users/":
                        obj.pop("password", None)
                        obj.setdefault("is_superuser", False)
                        obj.setdefault("is_staff", False)
                    if path == "/api/users/permissions/":
                        obj["users"] = [{"id": u} for u in b.get("users", [])]
                    fake.data[path].append(obj)
                    created.append(obj)
                return self._send(201, created if isinstance(body, list) else created[0])

            def do_PATCH(self):
                if not self._auth():
                    return
                path = urlparse(self.path).path
                fake.requests.append(("PATCH", path))
                body = self._body()
                parts = path.rstrip("/").rsplit("/", 1)
                if parts[1].isdigit():  # modification d'un seul objet : /api/…/<id>/
                    collection = parts[0] + "/"
                    obj = next((o for o in fake.data.get(collection, []) if o["id"] == int(parts[1])), None)
                    if obj is None:
                        return self._send(404, {"detail": "Not found"})
                    for k, v in body.items():
                        obj[k] = [{"id": u} for u in v] if (collection.endswith("permissions/") and k == "users") else v
                    return self._send(200, obj)
                err = fake._check_cf(body)
                if err:
                    return self._send(400, err)
                index = {o["id"]: o for o in fake.data[path]}
                for b in body:
                    obj = index[b["id"]]
                    if "custom_fields" in b:
                        obj["custom_fields"] = b["custom_fields"]
                    if "tags" in b:
                        obj["tags"] = [{"slug": t["slug"], "name": t["slug"]} for t in b["tags"]]
                return self._send(200, body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _check_cf(self, items):
        known = {cf["name"] for cf in self.data["/api/extras/custom-fields/"]}
        for b in items:
            unknown = set((b.get("custom_fields") or {})) - known
            if unknown:
                return {"custom_fields": [f"Champs inconnus : {sorted(unknown)}"]}
        return None

    def add(self, path, obj):
        self.next_id += 1
        obj = {"id": self.next_id, **obj}
        self.data[path].append(obj)
        return obj

    def ip(self, address):
        return next(o for o in self.data["/api/ipam/ip-addresses/"] if o["address"].split("/")[0] == address)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
