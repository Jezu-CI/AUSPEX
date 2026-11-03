# 6. Exports d'audit signés

`audit.py` produit, par référentiel, une archive qui rassemble les preuves
observables sur le réseau pour une période, signée pour qu'un auditeur
puisse vérifier qu'elle n'a pas été modifiée — **sans installer Auspex**.

## Production

- À la demande : `auspex audit export <nis2|dora|iec62443|iso27001|anssi>
  [--jours 30] [--fin now|logs|AAAA-MM-JJ]`.
- Automatiquement : section `audit` de `auspex.yaml` (`referentiels`,
  `frequence` quotidienne / hebdomadaire / mensuelle, `periode_jours`,
  `conserver` = 24 par défaut). Le service produit les exports échus
  **après un cycle réussi seulement** (des preuves périmées ne sont jamais
  signées) ; une erreur est journalisée sans arrêter le service.
- Archives dans `data/state/tableau/audits/`, nommées
  `auspex-audit-<référentiel>-<AAAAMMJJ>T<HHMM>Z.zip`, listées dans
  `index.json` et sur la page NetBox « Exports d'audit ».

## Contenu de l'archive

| Fichier | Contenu |
| --- | --- |
| `rapport.html` | rapport lisible et imprimable, exigence par exigence ; aucun script |
| `ecarts.csv` | écarts de la période (ouverts, résolus, dates) |
| `inventaire.csv` | actifs identifiés, zone, rapprochement NetBox |
| `regles.csv` | règles de flux en vigueur |
| `flux-inter-zones.csv` | flux entre zones et leur couverture par les règles |
| `donnees.json` | les mêmes preuves, pour un script |
| `MANIFEST.json` | référentiel, période, organisation, version, empreinte et taille de chaque fichier, export précédent |
| `MANIFEST.sig` | signature Ed25519 du manifeste |
| `cle-publique.pem` | clé publique de vérification |
| `SHA256SUMS` | empreintes au format `sha256sum -c` |
| `VERIFIER.txt` | mode d'emploi de la vérification |

Les valeurs vues sur le réseau (noms d'hôte…) sont neutralisées dans les CSV
(une cellule qui commence par `=`, `+`, `-`, `@`… n'est jamais une formule de
tableur) et échappées dans le rapport HTML.

## Statut d'une exigence

| Statut | Signification |
| --- | --- |
| `ecarts` | au moins un écart ouvert relevant de l'exigence — prioritaire sur tout le reste |
| `aucun_ecart` | données présentes, aucun écart observé sur la période |
| `preuve` | Auspex fournit une pièce (inventaire, règles, surveillance) sans juger |
| `non_evalue` | la donnée manque (pas de rapprochement NetBox, aucune règle chargée…) |

Pour chaque exigence, le rapport dit **ce qu'Auspex couvre** et **ce qui
reste à évaluer hors d'Auspex** (procédures, revues, organisation) : il ne
prétend jamais à plus que ce que le réseau montre.

| Référentiel | Exigences adossées aux preuves |
| --- | --- |
| NIS2 (règlement d'exécution 2024/2690) | §6.8 segmentation, §6.7 sécurité des réseaux, §12.4 inventaire, §3.2 surveillance |
| DORA (2022/2554, RTS 2024/1774) | art. 13 a), b), c), h), art. 8 |
| IEC 62443-3-3 | SR 5.1, SR 5.2, SR 6.2, SR 7.8 |
| ISO/IEC 27001:2022 | A.8.22, A.8.20, A.5.9, A.8.16 |
| ANSSI | administration en tiers, cloisonnement et filtrage, systèmes industriels, cartographie |

Un test n'admet dans le code que des références de sections vérifiées.

## Signature et chaînage

- Clé privée Ed25519 `data/state/cles/audit-ed25519.pem` (600, dossier 700),
  créée au premier export, jamais lisible par NetBox ; incluse dans les
  sauvegardes (qui sont donc à protéger).
- Empreinte de la clé : SHA-256 de la clé publique brute, 128 premiers bits
  par groupes de 4 (`auspex audit cle`, page NetBox). **C'est elle que
  l'exploitant communique à l'auditeur** : sans cette comparaison, la
  signature prouve l'intégrité, pas l'origine.
- **Chaînage** : le manifeste porte l'empreinte du manifeste de l'export
  précédent du même référentiel (`precedent`) ; une archive retirée ou
  remplacée dans la série se voit.
- Écriture atomique (fichier temporaire puis renommage) ; dates des entrées
  ZIP fixées à la fin de période.

## Vérification

Sans Auspex (OpenSSL 3, coreutils) :

```bash
openssl pkeyutl -verify -pubin -inkey cle-publique.pem -rawin \
    -in MANIFEST.json -sigfile MANIFEST.sig      # « Signature Verified Successfully »
sha256sum -c SHA256SUMS                          # « OK » pour chaque fichier
```

Avec Auspex : `auspex audit verify <archive.zip> --empreinte "<empreinte>"`
contrôle la signature, chaque empreinte, la présence de fichiers **ajoutés**
hors manifeste, et l'empreinte de la clé ; code de sortie 1 si l'archive est
altérée.
