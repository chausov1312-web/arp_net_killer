import random
import logging
from scapy.all import ARP, send, srp, Ether, conf, sr1

# Настройка логирования для scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def get_mac_by_arp(ip, timeout=3, retry=2):
    """Получение MAC адреса по IP через ARP запрос"""
    try:
        arp_req = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_req
        answered, _ = srp(packet, timeout=timeout, verbose=False, retry=retry)
        if answered:
            return answered[0][1].hwsrc
    except Exception as e:
        print(f"\033[1;33m[!] Ошибка ARP запроса к {ip}: {str(e)}\033[0m")
    return None

def aggressive_arp_ping(ip, timeout=0.5, retry=3):
    """Агрессивный ARP пинг с несколькими попытками"""
    for attempt in range(retry):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            
            # Используем sr1 с более агрессивными параметрами
            response = sr1(packet, timeout=timeout, verbose=False, retry=1)
            
            if response:
                return {
                    'ip': response.psrc,
                    'mac': response.hwsrc
                }
        except:
            pass
    return None

def generate_fake_mac():
    """Генерация случайного ложного MAC адреса"""
    return f"00:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:" \
           f"{random.randint(16, 99):02d}:{random.randint(16, 99):02d}:{random.randint(16, 99):02d}"
