# Contribuer

Merci de votre intérêt. Les contributions les plus utiles, de la plus simple
à la plus technique :

1. **Règles d'identification** (`rules/*.yaml`) : aucun code, uniquement des
   données. Une règle observe un log Zeek et vote pour un attribut.
2. **Correspondances réglementaires** : rattacher un type d'écart à un
   référentiel sectoriel.
3. **Importeurs de règles de flux** depuis les exports de pare-feu.
4. **Sorties d'alertes** vers d'autres SIEM ou outils de ticketing.
5. **Parsers de protocoles** industriels.

## Écrire une règle d'identification

```yaml
- id: it-mon-indice          # unique, préfixe it- ou ot-
  log: conn                  # type de log Zeek (conn, http, ssh, dhcp, ...)
  target: resp               # qui reçoit le vote : orig, resp, ou un champ IP
  match: { proto: tcp, id.resp_p: 1234 }
  set: { role: "Mon service" }
  weight: 0.5                # 0 < poids ≤ 1 ; un port seul reste un indice faible
```

Chaque règle doit être accompagnée d'un test dans `tests/test_fingerprint.py`
reproduisant l'enregistrement Zeek qui la déclenche. Les empreintes (bannières,
certificats, identités) doivent provenir de captures réelles, jamais de mémoire.

## Avant d'ouvrir une pull request

```bash
pip install -e ".[dev]"
pytest -q
```

- Une pull request = un sujet.
- Les messages, la documentation et les libellés visibles sont en français.
- Toute nouvelle fonctionnalité vient avec ses tests et la mise à jour de la
  documentation technique (`docs/`) dans la même pull request.
- Signer ses commits avec `git commit -s` (Developer Certificate of Origin).

## Principes non négociables

Une contribution qui ferait émettre des paquets à un capteur, demanderait des
identifiants sur les actifs ou stockerait un secret dans `auspex.yaml` sera
refusée, même optionnelle. Voir [SECURITY.md](SECURITY.md).

Les échanges sur le projet suivent le [code de conduite](CODE_OF_CONDUCT.md).

## Site web

Aperçu : `python tools/site.py --build` (résultat dans `build/site`). Les schémas
Mermaid sont pré-rendus en images : après avoir modifié ou ajouté un schéma
(README, `docs/`, `site/`), lancer `python tools/site.py --diagrammes`
(nécessite [Mermaid CLI](https://github.com/mermaid-js/mermaid-cli), `mmdc`) et
versionner les fichiers de `site/assets/diagrammes/`. Le site ne doit charger
aucune ressource depuis un autre domaine : la construction échoue sinon.
