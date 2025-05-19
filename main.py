import os
import platform
import subprocess
import threading
import logging
from datetime import datetime
from scapy.all import sniff, TCP, IP
import geoip2.database
import ipaddress

# Fichiers de logs
LOG_BANS = 'bans.log'
LOG_ALLOWED = 'allowed_ips.log'

# Configuration des journaux
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
ban_logger = logging.getLogger("ban")
ban_handler = logging.FileHandler(LOG_BANS)
ban_logger.addHandler(ban_handler)

allowed_logger = logging.getLogger("allowed")
allowed_handler = logging.FileHandler(LOG_ALLOWED)
allowed_logger.addHandler(allowed_handler)

# Base de données GeoIP (adapter le chemin si besoin)
GEOIP_DB = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

# Listes et seuils
banned_ips = set()
ip_attempts = {}
whitelist = {"192.168.80.1", "192.168.80.2"}  
lock = threading.Lock()

# VLAN et ranges spécifiques à bannir
vlans_to_block = [
    ipaddress.IPv4Network("10.31.10.0/24"),
    ipaddress.IPv4Network("10.31.20.0/24")
]

# Seuils de tentatives
THRESHOLD_BAD = 2
THRESHOLD_GOOD = 4

# Fonction de bannissement IP
def ban_ip(ip):
    with lock:
        if ip in banned_ips:
            return
        try:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            banned_ips.add(ip)
            ban_logger.info(f"IP bannie : {ip} sur {platform.system()}")
            print(f"[INFO] IP bannie : {ip}")
        except subprocess.CalledProcessError as e:
            ban_logger.error(f"Erreur bannissement de {ip} : {e}")
            print(f"[ERREUR] Bannissement échoué : {ip}")

# Vérifie si une IP est dans un des VLANs bloqués
def ip_in_banned_vlan(ip):
    ip_obj = ipaddress.IPv4Address(ip)
    return any(ip_obj in vlan for vlan in vlans_to_block)

# Vérifie la localisation géographique
def ip_from_france(ip):
    try:
        with geoip2.database.Reader(GEOIP_DB) as reader:
            response = reader.country(ip)
            return response.country.iso_code == "FR"
    except:
        return True  # Par défaut, bloquer si géolocalisation inconnue

# Analyse de chaque paquet
def analyse_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        ip_source = ip_layer.src

        # Si déjà banni, ignorer
        if ip_source in banned_ips:
            return

        # Bannissement VLAN ou géolocalisation
        if ip_in_banned_vlan(ip_source) or not ip_from_france(ip_source):
            ban_ip(ip_source)
            return

        with lock:
            if ip_source not in ip_attempts:
                ip_attempts[ip_source] = 1
            else:
                ip_attempts[ip_source] += 1

            if ip_source in whitelist:
                if ip_attempts[ip_source] >= THRESHOLD_GOOD:
                    ban_ip(ip_source)
                else:
                    allowed_logger.info(f"{ip_source} autorisée ({ip_attempts[ip_source]} tentative(s))")
            else:
                if ip_attempts[ip_source] >= THRESHOLD_BAD:
                    ban_ip(ip_source)
                else:
                    allowed_logger.info(f"{ip_source} non whitelistée - {ip_attempts[ip_source]} tentative(s)")

# Démarrage du sniffer
def start_sniffing():
    print("[INFO] Surveillance réseau sur le port 22 activée...")
    sniff(filter="tcp port 22", prn=analyse_packet, store=0)

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[INFO] Arrêt manuel.")
    except Exception as e:
        ban_logger.error(f"Erreur inattendue : {e}")
        print(f"[ERREUR] {e}")