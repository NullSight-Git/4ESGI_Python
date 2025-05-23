# 4ESGI_Python

- CASAGRANDE Michael
- VALLADE Allan
- CHAMBRE Ryan
- OUALI Mohammed
- FALANDRY Enzo

### Description
Ce script Python surveille les connexions SSH (port 22) en temps réel et applique automatiquement des règles de bannissement via iptables selon plusieurs critères :
- Blocage immédiat des IP issues de VLANs interdits.
- Blocage des IP dont la géolocalisation n’est pas la France.
- Comptage des tentatives par IP avec seuils différents pour les adresses en whitelist.
- Journalisation détaillée des actions dans deux fichiers de log.

### Fonctionnalités
- Sniffing réseau sur le port 22 à l’aide de Scapy.
- Géolocalisation des IP avec GeoLite2 (maxMind GeoIP2).
- Blocage iptables pour couper immédiatement l’accès.

### Seuils de tolérance :
- IP non‑whitelistée : bannissement dès la première tentative.
- IP whitelistée : tolérance jusqu’à 3 tentatives avant bannissement.
- Whitelist configurable pour IP de confiance.
- Blocage de VLANs définis via des plages CIDR.
- Journalisation des IP bannies et des IP autorisées/détectées, dans deux fichiers séparés.

### Prérequis
- Python 3.7+
- Modules Python :
- scapy
- geoip2
- ipaddress (intégré depuis Python 3.3)
- Fichier de base GeoIP2‑Country (format .mmdb), téléchargeable depuis MaxMind.
- Droits administrateur pour manipuler iptables.
  
![image](https://github.com/user-attachments/assets/6f05b7c2-f528-4eac-b43b-d4da8f77f34f)

# DEMANDE ET CONSIGNE

### TP noté – IDS Simplifié : Détection et Bannissement d’IP suspectes en Python
- Durée : 1h30
- Barème : note sur 20
- Niveau : Intermédiaire / Avancé
- OS cibles : Linux, macOS, Windows
- 
### Objectif général :
- Créer un système de détection d’intrusion (IDS) en Python capable de :
- Détecter les connexions entrantes vers le port 22.
- Extraire l’IP source et la bannir automatiquement via le pare-feu.
- Maintenir un journal des actions effectuées.

### Cahier des charges
1. Capture réseau en temps réel (4 pts)
- Analyse du trafic avec socket brut ou bibliothèque dédiée.
- Identification des paquets TCP avec destination port 22.
- Fonctionnement continu, non intrusif.
2. Détection et traitement des IPs (3 pts)
- Extraction correcte de l’IP source.
- Mécanisme de bannissement déclenché à la détection.
- Prévention des doublons (pas de rebannissement inutile).
3. Compatibilité multiplateforme (4 pts)
- Détection automatique du système d’exploitation (Windows, macOS, Linux).
- Commandes système conditionnelles :
  - Linux : iptables ou ufw
  - macOS : pfctl ou simulation
  - Windows : netsh advfirewall ou PowerShell
  - Appels système via subprocess robustes et discrets.
4. Journalisation des bannissements (4 pts)
- Fichier bans.log propre et horodaté.
- Contenu minimal requis : date/heure, IP bannie, OS.
- Pas de doublons ni écriture concurrente mal gérée.
5. Robustesse et qualité logicielle (5 pts)
- Le script doit pouvoir tourner indéfiniment sans planter.
- Gestion des erreurs et paquets invalides.
- Structure claire : séparation des responsabilités (sniffing, filtrage, bannissement, log).
- Aucune dépendance excessive ou superflue.
- Contraintes techniques
- Fonctionne avec élévation de privilège (sudo/root)
- Aucune solution clé-en-main (fail2ban, nmap, etc.)
- Bibliothèques autorisées : scapy, pyshark, ou équivalent
