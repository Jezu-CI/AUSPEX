---
title: Auspex — CMDB open source passive pour l'IT et l'OT (NetBox, Zeek)
description: "Auspex, CMDB open source et passive pour l'IT et l'OT : inventaire des actifs et contrôle de la segmentation réseau par écoute passive, sans agent, avec NetBox et Zeek. Preuves NIS2, DORA, IEC 62443."
hide:
  - navigation
  - toc
---

<div class="ax-hero" markdown>

<img src="assets/auspex-icon.svg" alt="" class="ax-hero-icon">

# Auspex

**La CMDB open source qui se remplit en écoutant le réseau** : inventaire
des actifs et contrôle de la segmentation par écoute passive, pour les
environnements IT et industriels (OT). Sans agent, sans
compte de service, sans émettre un seul paquet sur les réseaux surveillés.

<p class="ax-choix-titre">Vous cherchez plutôt…</p>

<div class="ax-choix">
  <a class="ax-choix-carte" href="utilisateur/">
    <span class="ax-choix-icone" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="28" height="28"><path d="m21.1 12.5 1.4 1.41-6.53 6.59L12.5 17l1.4-1.41 2.07 2.08zM10 17l3 3H3v-2c0-2.21 3.58-4 8-4l1.89.11zm1-13a4 4 0 0 1 4 4 4 4 0 0 1-4 4 4 4 0 0 1-4-4 4 4 0 0 1 4-4"/></svg></span>
    <strong>À utiliser Auspex</strong>
    <span>Installer, lire le tableau de bord, traiter les écarts, préparer un audit. En langage simple, sans jargon.</span>
    <span class="ax-choix-suite">Guide utilisateur →</span>
  </a>
  <a class="ax-choix-carte" href="guide/">
    <span class="ax-choix-icone" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="28" height="28"><path d="M12 8a4 4 0 0 1 4 4 4 4 0 0 1-4 4 4 4 0 0 1-4-4 4 4 0 0 1 4-4m0 2a2 2 0 0 0-2 2 2 2 0 0 0 2 2 2 2 0 0 0 2-2 2 2 0 0 0-2-2m-2 12c-.25 0-.46-.18-.5-.42l-.37-2.65c-.63-.25-1.17-.59-1.69-.99l-2.49 1.01c-.22.08-.49 0-.61-.22l-2-3.46a.493.493 0 0 1 .12-.64l2.11-1.66L4.5 12l.07-1-2.11-1.63a.493.493 0 0 1-.12-.64l2-3.46c.12-.22.39-.31.61-.22l2.49 1c.52-.39 1.06-.73 1.69-.98l.37-2.65c.04-.24.25-.42.5-.42h4c.25 0 .46.18.5.42l.37 2.65c.63.25 1.17.59 1.69.98l2.49-1c.22-.09.49 0 .61.22l2 3.46c.13.22.07.49-.12.64L19.43 11l.07 1-.07 1 2.11 1.63c.19.15.25.42.12.64l-2 3.46c-.12.22-.39.31-.61.22l-2.49-1c-.52.39-1.06.73-1.69.98l-.37 2.65c-.04.24-.25.42-.5.42zm1.25-18-.37 2.61c-1.2.25-2.26.89-3.03 1.78L5.44 7.35l-.75 1.3L6.8 10.2a5.55 5.55 0 0 0 0 3.6l-2.12 1.56.75 1.3 2.43-1.04c.77.88 1.82 1.52 3.01 1.76l.37 2.62h1.52l.37-2.61c1.19-.25 2.24-.89 3.01-1.77l2.43 1.04.75-1.3-2.12-1.55c.4-1.17.4-2.44 0-3.61l2.11-1.55-.75-1.3-2.41 1.04a5.42 5.42 0 0 0-3.03-1.77L12.75 4z"/></svg></span>
    <strong>La technique</strong>
    <span>Architecture, chaque réglage, authentification, capteurs, formats d'export, sécurité et preuves automatisées.</span>
    <span class="ax-choix-suite">Documentation technique →</span>
  </a>
</div>

[Télécharger](telecharger.md){ .md-button .md-button--primary }
[Code source](https://github.com/Jezu-CI/AUSPEX){ .md-button }

<small>Open source, licence AGPL v3 · conçu par Yann Mathon · [English summary](en/index.md){ hreflang=en lang=en }</small>

</div>

*À Rome, l'auspex lisait les présages en observant le vol des oiseaux, sans
jamais intervenir. C'est le principe de l'outil : tout voir, ne rien émettre.*

## Auspex en vidéo { #video }

Deux minutes sur un vrai central, avec sept jours de trafic d'un site IT et
industriel de démonstration : connexion, tableau de bord, écarts de
segmentation, carte des flux, rapport d'audit NIS2 signé.

<div class="ax-video">
<video controls preload="none" playsinline width="1280" height="720"
       poster="assets/video/auspex-demo-apercu.jpg">
  <source src="assets/video/auspex-demo.mp4" type="video/mp4">
  <a href="assets/video/auspex-demo.mp4">Télécharger la vidéo (MP4, 1,5 Mo)</a>
</video>
</div>

<small>Vidéo hébergée sur ce site, sans service tiers ; elle ne se charge que
si vous cliquez sur lecture. Elle est enregistrée automatiquement par
l'intégration continue, à partir du produit réel.</small>

## Ce qu'Auspex apporte

<div class="grid cards ax-cards" markdown>

-   :material-radar: **Inventaire observé, pas déclaré**

    ---

    Chaque actif vu sur le réseau est identifié (système, fabricant, modèle,
    firmware, rôle) avec un score de confiance et la liste de ses indices.
    Automates Siemens, superviseurs Niagara, passerelles HART, équipements
    Moxa, Hirschmann, RUGGEDCOM… IHM et stations d'ingénierie distinguées.

-   :material-shield-check: **Segmentation contrôlée en continu**

    ---

    Chaque flux entre zones est comparé aux règles déclarées (CSV ou Excel) :
    flux non déclarés, règles expirées encore utilisées, administration
    depuis un tier moins sensible, flux IT vers OT sans DMZ industrielle.

-   :material-file-certificate: **Preuves pour NIS2, DORA, IEC 62443**

    ---

    Exports d'audit signés par référentiel, vérifiables sans Auspex ; chaque
    écart porte ses références réglementaires ; alertes vers le SIEM.

-   :material-database-sync: **Intégré à NetBox**

    ---

    L'inventaire observé s'écrit à côté de l'inventaire déclaré, avec les
    écarts entre les deux. Tableau de bord, carte interactive, contrôle
    d'accès renforcé (MFA, clé de sécurité, carte à puce, LDAPS, OIDC, SAML).

</div>

## En images

<div class="ax-shots" markdown>

<figure markdown>
  [![Tableau de bord](assets/captures/12-tableau-de-bord.png)](captures.md)
  <figcaption>Tableau de bord : écarts ouverts, état du service, inventaire, matrice des zones</figcaption>
</figure>

<figure markdown>
  [![Carte des actifs](assets/captures/14-carte.png)](captures.md)
  <figcaption>Carte : zones de gestion à gauche, zones industrielles à droite, flux en écart en rouge</figcaption>
</figure>

<figure markdown>
  [![Détail d'un actif](assets/captures/15-carte-selection.png)](captures.md)
  <figcaption>Détail d'un actif : identification, indices, écarts et flux</figcaption>
</figure>

<figure markdown>
  [![Rapport d'audit NIS2](assets/captures/18-rapport-synthese.png)](captures.md)
  <figcaption>Export d'audit NIS2 signé : constat par exigence</figcaption>
</figure>

</div>

[Toutes les captures d'écran](captures.md){ .md-button }

## Comment ça marche

```mermaid
flowchart LR
  TAP["Port miroir / TAP"] -- "copie du trafic" --> S["Capteur<br/>Zeek + ICSNPP"]
  S -- "logs (SSH, écriture seule)" --> C["Central<br/>Auspex"]
  C -- "inventaire observé, écarts" --> N["NetBox"]
  C -- "alertes" --> SIEM["SIEM"]
  C -- "exports signés" --> A["Audit"]
```

1. **Le capteur écoute** un port miroir ou un TAP (image Docker, ou appliance
   ISO durcie dont l'interface d'écoute n'émet rien).
2. **Le central analyse** : identification des actifs, conformité des flux,
   rapprochement avec NetBox, alertes et exports d'audit.
3. **Les équipes consultent** dans NetBox, reçoivent les alertes dans leur
   SIEM, transmettent les exports aux auditeurs.

## Prouvé, pas promis

Chaque modification est vérifiée automatiquement sur le **vrai produit** :
installation complète du central, vrai NetBox, vrai navigateur, vrai
annuaire et vrais fournisseurs d'identité, appliance démarrée en machine
virtuelle (aucune trame émise sur l'écoute), et **captures industrielles
réelles** (66 identifications attendues, faux positifs compris).
[Le détail des preuves](documentation/06-preuves-ci.md).

Les pratiques de sécurité du projet sont évaluées publiquement par l'OpenSSF
(fondation de la Linux Foundation pour la sécurité de l'open source) :
[fiche OpenSSF Best Practices](https://www.bestpractices.dev/projects/16662) et
[analyse OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Jezu-CI/AUSPEX).
