import os
import platform
import subprocess
import threading
import logging
from datetime import datetime
from scapy.all import sniff, TCP, IP
import geoip2.database
import ipaddress

# Chemins des fichiers de logs
LOG_BANS = 'bans.log'
LOG_ALLOWED = 'allowed_ips.log'

# Configuration des logs : format d'affichage, niveau, etc.
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Logger pour les IP bannies
ban_logger = logging.getLogger("ban")
ban_handler = logging.FileHandler(LOG_BANS)
ban_logger.addHandler(ban_handler)

# Logger pour les IP autorisées ou surveillées
allowed_logger = logging.getLogger("allowed")
allowed_handler = logging.FileHandler(LOG_ALLOWED)
allowed_logger.addHandler(allowed_handler)

# Chemin vers la base GeoIP (penser à l’adapter selon l’emplacement local)
GEOIP_DB = "/home/kalii/GeoLite2-Country_20250516"

# Structures en mémoire pour garder les IP traitées
banned_ips = set()           # Ensemble des IP déjà bannies
ip_attempts = {}             # Dictionnaire des tentatives par IP
whitelist = {"192.168.80.1", "192.168.80.2"}  # IP autorisées (liste blanche)
lock = threading.Lock()      # Pour sécuriser les accès en multithreading

# Réseaux (VLANs) à bloquer par défaut
vlans_to_block = [
    ipaddress.IPv4Network("10.31.10.0/24"),
    ipaddress.IPv4Network("10.31.20.0/24")
]

# Seuils de tentatives
THRESHOLD_BAD = 1     # Nombre de tentatives max pour IP non whitelistée avant ban
THRESHOLD_GOOD = 3    # Pour IP dans la whitelist, on autorise un peu plus

# Fonction pour bannir une IP via iptables
def ban_ip(ip):
    with lock:  # Pour éviter les accès concurrents à banned_ips
        if ip in banned_ips:
            return  # Déjà banni, inutile de recommencer
        try:
            # Ajout d’une règle iptables pour bloquer l’IP
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            banned_ips.add(ip)
            ban_logger.info(f"IP bannie : {ip} sur {platform.system()}")
            print(f"[INFO] IP bannie : {ip}")
        except subprocess.CalledProcessError as e:
            # En cas d’erreur avec iptables
            ban_logger.error(f"Erreur bannissement de {ip} : {e}")
            print(f"[ERREUR] Bannissement échoué : {ip}")

# Vérifie si l'IP appartient à un VLAN interdit
def ip_in_banned_vlan(ip):
    ip_obj = ipaddress.IPv4Address(ip)
    return any(ip_obj in vlan for vlan in vlans_to_block)

# Vérifie si l'IP vient de France via GeoIP
def ip_from_france(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            return response.country.iso_code == "FR"
    except:
        # Si la géoloc échoue, on considère l'IP comme suspecte
        return False

# Fonction appelée pour chaque paquet capturé
def analyse_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        ip_source = ip_layer.src

        # Si l’IP est déjà bannie, on ne fait rien
        if ip_source in banned_ips:
            return

        # Si l’IP est dans un VLAN interdit ou ne vient pas de France → on bannit direct
        if ip_in_banned_vlan(ip_source) or not ip_from_france(ip_source):
            ban_ip(ip_source)
            return

        with lock:
            # Mise à jour du nombre de tentatives de connexion de l'IP
            if ip_source not in ip_attempts:
                ip_attempts[ip_source] = 1
            else:
                ip_attempts[ip_source] += 1

            # Traitement des IP whitelistées
            if ip_source in whitelist:
                if ip_attempts[ip_source] >= THRESHOLD_GOOD:
                    ban_ip(ip_source)
                else:
                    allowed_logger.info(f"{ip_source} autorisée ({ip_attempts[ip_source]} tentative(s))")
            else:
                # Pour les IP normales
                if ip_attempts[ip_source] >= THRESHOLD_BAD:
                    ban_ip(ip_source)
                else:
                    allowed_logger.info(f"{ip_source} non whitelistée - {ip_attempts[ip_source]} tentative(s)")

# Démarre le sniffing réseau sur le port 22 (SSH)
def start_sniffing():
    print("[INFO] Surveillance réseau sur le port 22 activée...")
    sniff(filter="tcp port 22", prn=analyse_packet, store=0)

# Lancement principal du programme
if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt manuel.")
    except Exception as e:
        ban_logger.error(f"Erreur inattendue : {e}")
        print(f"[ERREUR] {e}")
