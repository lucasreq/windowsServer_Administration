#  Gestion des comptes Windows server

Auteur du script: Antoine Thys

Ce script a été fait pour déployer des utilisateurs sur un serveur Windows.

Il est décomposé en 3 étapes:
1. La creation des unités d'organisations (OU)
2. La creation des dossiers de partage
3. La creation des utilisateurs

Afin de les executer vous devez lancer le script pour chaque étapes.

ex : 
1. C:\Scripts\MonScript.ps1 -Arg1 'OU'
2. C:\Scripts\MonScript.ps1 -Arg1 'Share'
3. C:\Scripts\MonScript.ps1 -Arg1 'User'