# Module Auspex : exemple de règles

Gabarit de module de règles d'identification pour [Auspex](https://github.com/Jezu-CI/AUSPEX).

## Utiliser ce module

Dans `auspex.yaml` :

```yaml
modules:
  - github.com/<organisation>/<ce-depot>@v0.1.0
```

puis `auspex plan` et `auspex apply`.

## Publier une version

1. Modifier les règles dans `rules/`.
2. Vérifier : `auspex module check .`
3. Mettre à jour `version` dans `module.yaml`, puis créer le tag correspondant :
   `git tag v0.2.0 && git push --tags`.

Un tag publié ne doit jamais être déplacé : Auspex retient le commit de chaque
version et refuse d'installer un tag qui a changé de contenu.

## Règles du jeu

- Uniquement des données (YAML, JSON, CSV, texte) : un module contenant un
  script ou un exécutable est refusé à l'installation.
- Identifiants de règles préfixés par le nom du module, pour éviter les collisions.
- Ajouter le topic GitHub `auspex-module` au dépôt pour qu'il soit trouvé.
