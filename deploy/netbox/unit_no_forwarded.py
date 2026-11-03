"""Supprime la réécriture de l'adresse source par X-Forwarded-For dans la
configuration NGINX Unit de l'image NetBox (voir deploy/netbox/Dockerfile).

Échoue si le fichier n'a pas la forme attendue : mieux vaut une construction
d'image en erreur qu'un contournement silencieux de la restriction par IP.
"""
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    conf = json.load(fh)
listeners = conf.get("listeners")
if not isinstance(listeners, dict) or not listeners:
    sys.exit(f"{path} : aucun « listener » trouvé, format inattendu")
# « forwarded » (Unit ≥ 1.29) ; « client_ip » (Unit 1.28, ancien nom)
removed = [name for name, listener in listeners.items()
           if [listener.pop(k) for k in ("forwarded", "client_ip") if k in listener]]
with open(path, "w", encoding="utf-8") as fh:
    json.dump(conf, fh, indent=2)
remaining = json.dumps(conf)
if '"forwarded"' in remaining or '"client_ip"' in remaining or "x-forwarded-for" in remaining.lower():
    sys.exit(f"{path} : une réécriture par X-Forwarded-For subsiste")
print(f"NGINX Unit : réécriture par X-Forwarded-For supprimée sur {len(removed)} listener(s) "
      f"({', '.join(removed) or 'aucun ne l avait'})")
