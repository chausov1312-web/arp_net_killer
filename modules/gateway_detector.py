import subprocess
from scapy.all import ARP, srp, Ether, conf

def get_gateway_info():
    """Автоматическое получение шлюза с множеством альтернативных методов"""
    gateway_ip = None
    gateway_mac = None
    
    methods = [
        ("ip route (Linux)", "ip route | grep default | head -1"),
        ("route -n", "route -n 2>/dev/null | grep '^0.0.0.0' | head -1"),
        ("netstat -rn", "netstat -rn 2>/dev/null | grep '^0.0.0.0' | head -1"),
        ("ip -4 route", "ip -4 route show default 2>/dev/null | head -1"),
        ("Termux: netstat", "netstat -rn 2>/dev/null | grep UG | head -1"),
        ("ip neigh show", "ip neigh show 2>/dev/null | grep 'router' | head -1"),
    ]
    
    print(f"\033[1;33m[*] Ищу шлюз различными методами...\033[0m")
    
    # Метод 1: Перебираем все способы получения IP шлюза
    for method_name, cmd in methods:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                
                # Парсим вывод в зависимости от формата
                if "ip route" in cmd or "ip -4 route" in cmd:
                    # Формат: default via 192.168.1.1 dev wlan0
                    parts = output.split()
                    if "via" in parts:
                        idx = parts.index("via") + 1
                        if idx < len(parts):
                            gateway_ip = parts[idx]
                elif "route -n" in cmd or "netstat -rn" in cmd:
                    # Формат: 0.0.0.0 192.168.1.1 0.0.0.0 UG
                    parts = output.split()
                    if len(parts) >= 2:
                        gateway_ip = parts[1]
                elif "ip neigh show" in cmd:
                    # Формат: 192.168.1.1 dev wlan0 lladdr xx:xx:xx:xx:xx:xx REACHABLE
                    parts = output.split()
                    if len(parts) >= 1:
                        gateway_ip = parts[0]
                
                if gateway_ip and gateway_ip != "0.0.0.0":
                    print(f"  \033[1;32m[✓] Метод '{method_name}': найден шлюз {gateway_ip}\033[0m")
                    break
                else:
                    print(f"  \033[1;33m[!] Метод '{method_name}': не удалось извлечь IP\033[0m")
                    
        except (subprocess.TimeoutExpired, Exception) as e:
            print(f"  \033[1;33m[!] Метод '{method_name}' не сработал: {str(e)}\033[0m")
            continue
    
    # Метод 2: Если стандартные методы не помогли, пробуем получить через DNS или сетевые настройки
    if not gateway_ip:
        print(f"  \033[1;33m[*] Стандартные методы не сработали, пробую альтернативные...\033[0m")
        
        # Попытка получить через resolv.conf (обычно указывает на шлюз как DNS)
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.startswith("nameserver"):
                        dns_server = line.split()[1]
                        # Проверяем, является ли DNS локальным IP
                        if dns_server.startswith("192.168.") or \
                           dns_server.startswith("10.") or \
                           dns_server.startswith("172.16.") or \
                           dns_server.startswith("172.31."):
                            gateway_ip = dns_server
                            print(f"  \033[1;32m[✓] Найден шлюз через resolv.conf: {gateway_ip}\033[0m")
                            break
        except:
            pass
        
        # Метод для Termux: использование getprop (Android)
        if not gateway_ip:
            try:
                # В Android можно попробовать получить через системные свойства
                result = subprocess.run(
                    "getprop | grep -E '(net.dns|dhcp.*gateway)'",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if "gateway" in line.lower() or "dns" in line.lower():
                            parts = line.split(':')
                            if len(parts) > 1:
                                ip_candidate = parts[1].strip().strip('[]')
                                # Проверяем, что это IP адрес
                                if '.' in ip_candidate and ip_candidate.count('.') == 3:
                                    gateway_ip = ip_candidate
                                    print(f"  \033[1;32m[✓] Найден шлюз через getprop: {gateway_ip}\033[0m")
                                    break
            except:
                pass
        
        # Метод 3: Пробуем определить шлюз по последнему октету (часто .1 или .254)
        if not gateway_ip:
            try:
                # Получаем свой IP
                result = subprocess.run(
                    "ip -4 addr show | grep inet | head -1",
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if result.returncode == 0:
                    ip_line = result.stdout.strip()
                    if ip_line:
                        own_ip = ip_line.split()[1].split('/')[0]
                        ip_parts = own_ip.split('.')
                        if len(ip_parts) == 4:
                            # Пробуем распространенные адреса шлюза
                            common_gateways = [
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.1",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.254",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.100",
                                f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.2",
                            ]
                            
                            # Проверяем каждый возможный шлюз
                            for test_gateway in common_gateways:
                                try:
                                    # Быстрый ARP пинг
                                    arp_req = ARP(pdst=test_gateway)
                                    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                                    packet = broadcast / arp_req
                                    answered, _ = srp(packet, timeout=0.5, verbose=False, retry=1)
                                    if answered:
                                        gateway_ip = test_gateway
                                        print(f"  \033[1;32m[✓] Определен шлюз по паттерну: {gateway_ip}\033[0m")
                                        break
                                except:
                                    continue
            except:
                pass
    
    # Метод 4: Если IP найден, но нет MAC - спрашиваем пользователя
    if not gateway_ip:
        print(f"  \033[1;33m[!] Не удалось автоматически определить IP шлюза\033[0m")
        return None, None
    
    # Теперь ищем MAC адрес шлюза
    print(f"  \033[1;33m[*] Определяю MAC адрес шлюза {gateway_ip}...\033[0m")
    
    mac_methods = [
        ("ARP таблица", f"ip neigh show {gateway_ip} 2>/dev/null | awk '{{print $5}}'"),
        ("arp -a", f"arp -a {gateway_ip} 2>/dev/null | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'"),
        ("arp -n", f"arp -n {gateway_ip} 2>/dev/null | grep -o -E '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}'"),
    ]
    
    for method_name, cmd in mac_methods:
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                gateway_mac = result.stdout.strip()
                print(f"  \033[1;32m[✓] MAC из {method_name}: {gateway_mac}\033[0m")
                break
        except:
            continue
    
    # Если MAC не нашелся в таблицах, делаем ARP запрос
    if not gateway_mac:
        print(f"  \033[1;33m[*] Делаю ARP запрос к шлюзу {gateway_ip}...\033[0m")
        
        # Пробуем несколько раз с разными таймаутами
        for attempt in range(3):
            timeout = 0.5 * (attempt + 1)  # 0.5, 1.0, 1.5 секунды
            retries = attempt + 1  # 1, 2, 3 попытки
            
            try:
                arp_req = ARP(pdst=gateway_ip)
                broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = broadcast / arp_req
                answered, _ = srp(
                    packet, 
                    timeout=timeout, 
                    verbose=False, 
                    retry=retries,
                    iface_hint=conf.iface
                )
                
                if answered:
                    gateway_mac = answered[0][1].hwsrc
                    print(f"  \033[1;32m[✓] MAC получен через ARP запрос: {gateway_mac}\033[0m")
                    break
                else:
                    print(f"  \033[1;33m[!] Попытка {attempt+1}: ARP запрос не ответил\033[0m")
            except Exception as e:
                print(f"  \033[1;33m[!] Ошибка ARP запроса: {str(e)}\033[0m")
    
    # Если всё еще нет MAC, пробуем сканировать всю подсеть
    if not gateway_mac:
        print(f"  \033[1;33m[*] Пробую сканировать подсеть для поиска шлюза...\033[0m")
        
        try:
            # Получаем свою подсеть
            result = subprocess.run(
                "ip -4 addr show | grep inet | head -1",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                ip_info = result.stdout.strip().split()[1]
                network_addr = ip_info.split('/')[0]
                mask = ip_info.split('/')[1]
                
                # Сканируем несколько адресов вокруг предполагаемого шлюза
                ip_parts = network_addr.split('.')
                if len(ip_parts) == 4:
                    base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                    
                    # Список адресов для проверки (типичные адреса шлюза)
                    test_ips = [
                        f"{base}.1", f"{base}.254", f"{base}.100",
                        f"{base}.2", f"{base}.253", gateway_ip
                    ]
                    
                    for test_ip in test_ips:
                        if test_ip == network_addr:  # Пропускаем свой IP
                            continue
                            
                        try:
                            arp_req = ARP(pdst=test_ip)
                            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                            packet = broadcast / arp_req
                            answered, _ = srp(packet, timeout=0.3, verbose=False, retry=1)
                            
                            if answered:
                                gateway_mac = answered[0][1].hwsrc
                                gateway_ip = test_ip  # Обновляем IP на найденный
                                print(f"  \033[1;32m[✓] Найден активный шлюз: {gateway_ip} ({gateway_mac})\033[0m")
                                break
                        except:
                            continue
        except Exception as e:
            print(f"  \033[1;33m[!] Ошибка при сканировании: {str(e)}\033[0m")
    
    # Если MAC так и не найден, возвращаем только IP
    if gateway_ip and not gateway_mac:
        print(f"  \033[1;33m[⚠] MAC шлюза не найден, но IP определен: {gateway_ip}\033[0m")
        print(f"  \033[1;34m[?] MAC будет запрошен у пользователя или определен позже\033[0m")
        return gateway_ip, None
    
    if gateway_ip and gateway_mac:
        print(f"  \033[1;32m[✓] Шлюз успешно определен: {gateway_ip} ({gateway_mac})\033[0m")
        return gateway_ip, gateway_mac
    
    return None, None
