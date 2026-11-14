"""Auspex : CMDB passive IT/OT.

L'auspex, à Rome, lisait les présages en observant le vol des oiseaux,
sans jamais intervenir. C'est le principe du projet : tout voir, ne rien émettre.

Ce package ne dépend ni de NetBox ni de Zeek pour fonctionner : il traite des
observations (logs Zeek au format JSON) et une configuration déclarative, et
produit des identifications d'actifs, des écarts de conformité et des alertes.
"""

__version__ = "0.2.0"

# Chaque version porte un nom de code, dans l'esprit des noms de vaisseaux.
__codename__ = "Lantern in the Void"
