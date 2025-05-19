#!/usr/bin/env python3
import platform
import subprocess
import threading
import logging
from scapy.all import sniff, IP
import geoip2.database
import ipaddress

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION GLOBALE
# ─────────────────────────────────────────────────────────────────────────────

# Fichiers de logs : bans.log pour les blocages, allowed_ips.log pour les connexions autorisées
LOG_BANS    = 'bans.log'
LOG_ALLOWED = 'allowed_ips.log'

# Chemin vers la base GeoIP2 (.mmdb) pour la géolocalisation
GEOIP_DB    = "/home/kalii/GeoLite2-Country.mmdb"

# IP de confiance (whitelist) : on leur donne un peu plus de tolérance
whitelist = {
    "192.168.80.1",
    "192.168.80.2",
    "192.168.80.133",  # mon Kali
}

# VLANs (plages CIDR) à bloquer automatiquement
vlans_to_block = [
    ipaddress.IPv4Network("10.31.10.0/24"),
    ipaddress.IPv4Network("10.31.20.0/24"),
]

# Seuil de tentatives avant bannissement
THRESHOLD_BAD  = 1   # pour IP non-whitelistées
THRESHOLD_GOOD = 3   # pour IP whitelistées

# Structures en mémoire pour suivre les IP
banned_ips  = set()  # IP déjà bloquées
ip_attempts = {}     # compteur de tentatives par IP
lock        = threading.Lock()  # pour éviter les conflits en multithreading


# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION DES LOGGERS
# ─────────────────────────────────────────────────────────────────────────────

# Formatter commun qui ajoute date et heure à chaque message
formatter = logging.Formatter(
    fmt='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Logger pour les bannissements
ban_logger = logging.getLogger("ban")
ban_logger.setLevel(logging.INFO)
ban_logger.propagate = False  # ne pas répercuter au logger racine

# FileHandler pour écrire dans bans.log
ban_fh = logging.FileHandler(LOG_BANS)
ban_fh.setFormatter(formatter)
ban_logger.addHandler(ban_fh)

# StreamHandler pour afficher en console le même message
ban_ch = logging.StreamHandler()
ban_ch.setFormatter(formatter)
ban_logger.addHandler(ban_ch)

# Logger pour les IP autorisées/surveillées
allowed_logger = logging.getLogger("allowed")
allowed_logger.setLevel(logging.INFO)
allowed_logger.propagate = False

# FileHandler pour écrire dans allowed_ips.log
allowed_fh = logging.FileHandler(LOG_ALLOWED)
allowed_fh.setFormatter(formatter)
allowed_logger.addHandler(allowed_fh)


# ─────────────────────────────────────────────────────────────────────────────
# FONCTIONS PRINCIPALES
# ─────────────────────────────────────────────────────────────────────────────

def ban_ip(ip: str):
    """
    Bloque l'IP avec iptables puis logue :
    - date/heure
    - IP
    - OS (Linux, etc.)
    - nombre de tentatives
    """
    with lock:
        if ip in banned_ips:
            return  # déjà bloquée, on sort
        attempts = ip_attempts.get(ip, 0)  # récupère le nombre de tentatives
        try:
            # Ajoute une règle iptables pour DROP les paquets venant de l'IP
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            banned_ips.add(ip)  # marque comme bloquée
            # Message unique combinant toutes les infos
            msg = f"IP bannie : {ip} - OS : {platform.system()} - Tentatives : {attempts}"
            ban_logger.info(msg)
        except subprocess.CalledProcessError as e:
            ban_logger.error(f"Échec bannissement {ip} : {e}")


def ip_in_banned_vlan(ip: str) -> bool:
    """
    Retourne True si l'IP appartient à l'une des plages VLAN interdites.
    """
    ip_obj = ipaddress.IPv4Address(ip)
    return any(ip_obj in vlan for vlan in vlans_to_block)


def ip_from_france(ip: str) -> bool:
    """
    - Si IP privée (192.168.x.x, 10.x.x.x...), on la considère "locale" → True
    - Sinon on interroge GeoIP2 pour vérifier si c'est en France
    """
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        if ip_obj.is_private:
            return True  # IP interne, on autorise
        # Lecture de la DB GeoIP
        with geoip2.database.Reader(GEOIP_DB) as reader:
            return reader.country(ip).country.iso_code == "FR"
    except Exception:
        return False  # en cas d'erreur, on considère suspect


def analyse_packet(packet):
    """
    Pour chaque paquet capturé :
    1) ignore si déjà bannie
    2) bannit si VLAN interdit ou IP hors-France
    3) sinon incrémente le compteur de tentatives
    4) applique les seuils whitelist/non-whitelist
    """
    if not packet.haslayer(IP):
        return

    ip_src = packet[IP].src

    # 1) si déjà bloquée, on ne fait rien
    if ip_src in banned_ips:
        return

    # 2) bannissement direct pour VLAN interdit ou géoloc hors-France
    if ip_in_banned_vlan(ip_src) or not ip_from_france(ip_src):
        ban_ip(ip_src)
        return

    # 3) comptage des tentatives
    with lock:
        ip_attempts[ip_src] = ip_attempts.get(ip_src, 0) + 1
        attempts = ip_attempts[ip_src]

    # 4) application des seuils selon whitelist
    if ip_src in whitelist:
        if attempts >= THRESHOLD_GOOD:
            ban_ip(ip_src)
        else:
            allowed_logger.info(f"{ip_src} autorisée ({attempts} tentative(s))")
    else:
        if attempts >= THRESHOLD_BAD:
            ban_ip(ip_src)
        else:
            allowed_logger.info(f"{ip_src} non-whitelistée - {attempts} tentative(s)")


def start_sniffing():
    """
    Démarre le sniffing Scapy sur le port SSH (22).
    """
    ban_logger.info("Surveillance réseau sur le port 22 activée…")
    sniff(filter="tcp port 22", prn=analyse_packet, store=0)


# ─────────────────────────────────────────────────────────────────────────────
# POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        ban_logger.info("Arrêt manuel.")
    except Exception as e:
        ban_logger.error(f"Erreur inattendue : {e}")
