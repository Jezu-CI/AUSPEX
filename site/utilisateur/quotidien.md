---
title: Auspex au quotidien
description: "Utiliser Auspex au quotidien : la routine hebdomadaire, les mises à jour, les sauvegardes, et que faire quand quelque chose ne fonctionne pas."
---

# Au quotidien et en cas de problème

## La routine

**Chaque jour (2 minutes)** : un coup d'œil au tableau de bord.

- « État du service » est vert et le dernier cycle est récent ?
- Un nouvel écart **critique** ?
- Des **nouveaux actifs** depuis hier ?

**Chaque semaine (30 minutes)** :

- traiter les écarts de gravité élevée ;
- identifier les adresses « Observé par Auspex » dans l'inventaire ;
- regarder les règles qui expirent bientôt (widget « État du service ») et
  prévenir leurs propriétaires.

**Chaque mois** :

- faire le ménage dans les règles jamais utilisées ;
- relire le rapport d'audit du mois avec le responsable de la conformité ;
- vérifier qu'une mise à jour d'Auspex est disponible (voir plus bas).

## Mettre Auspex à jour

Sur le central, depuis le dossier `deploy` :

```bash
./update.sh
```

Le script sauvegarde tout (base NetBox, état d'Auspex, secrets), installe la
nouvelle version, redémarre et vérifie que tout fonctionne. **Si une
vérification échoue, il remet tout comme avant**, base de données comprise.

## Sauvegarder

`update.sh` sauvegarde avant chaque mise à jour. Pour une sauvegarde à la
demande :

```bash
docker compose exec auspex auspex backup
```

L'archive contient l'état d'Auspex, sa configuration et la clé qui signe
les rapports d'audit : **rangez-la en lieu sûr**. La base NetBox se
sauvegarde à part, comme toute base PostgreSQL.

## En cas de problème

| Ce que vous constatez | Cause probable | Que faire |
| --- | --- | --- |
| le dernier cycle est ancien, ou « dernier cycle en erreur » | NetBox injoignable, fichier de règles invalide | `docker compose exec auspex auspex health` donne la cause ; `auspex validate` liste les erreurs de configuration |
| aucun écart, aucune alerte, alors que le trafic arrive | la configuration n'est pas complète : Auspex suspend l'analyse plutôt que d'inventer des écarts | `auspex plan` montre ce qui manque |
| plus personne ne peut se connecter, sauf l'administrateur | `auspex.yaml` est devenu invalide : NetBox se verrouille par sécurité | corrigez le fichier (`auspex validate`) ; c'est relu sans redémarrage |
| un utilisateur voit « Accès refusé » (403) | il se connecte depuis une adresse non autorisée pour son compte | vérifiez les règles d'accès de son compte ([Se connecter](connexion.md)) |
| un utilisateur a perdu son téléphone, ou son compte est verrouillé | — | `auspex_mfa unlock` ou `reset` ([Se connecter](connexion.md#débloquer-un-compte-administrateur)) |
| toutes les cartes à puce sont refusées | la liste de révocation des cartes a expiré | renouvelez-la ; Auspex prévient 7 jours avant |
| un capteur n'envoie plus rien | mauvaise empreinte du central, capteur non déclaré, adresse non autorisée | regardez l'écran du capteur, puis `auspex capteur liste` sur le central |
| des alertes restent « en attente » | le SIEM est injoignable | rien n'est perdu ; `auspex alerts test` une fois le SIEM revenu |
| une machine reste « non identifiée » | pas assez d'indices dans le trafic observé | patientez quelques jours, ou identifiez-la à la main dans NetBox |
| un équipement connu n'apparaît pas | il ne communique pas sur les liens écoutés | vérifiez que le port miroir couvre bien son VLAN ou son commutateur |

Les commandes s'exécutent sur le central, depuis le dossier `deploy`, en les
préfixant par `docker compose exec auspex`. Le détail de chaque cas est dans
la [documentation technique](../documentation/04-exploitation.md#dépannage).

## Obtenir de l'aide

- [Questions fréquentes](../faq.md)
- [Signaler un problème ou proposer une amélioration](https://github.com/Jezu-CI/AUSPEX/issues)
- [Signaler une faille de sécurité](../securite.md)
