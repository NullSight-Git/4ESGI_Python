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

