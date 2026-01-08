import subprocess

def get_interfaces():
    """Получение сетевых интерфейсов"""
    interfaces = []
    try:
        output = subprocess.check_output(
            "ip -o link show | awk -F': ' '{print $2}' | grep -E '^(en|eth|wlan|wl|usb)' | sort",
            shell=True, text=True
        ).strip().split('\n')
        interfaces = [iface for iface in output if iface]
    except:
        # Резервные варианты
        try:
            output = subprocess.check_output(
                "ifconfig -a | grep -o '^[a-zA-Z0-9]*' | grep -v 'lo'",
                shell=True, text=True
            ).strip().split('\n')
            interfaces = [iface for iface in output if iface]
        except:
            interfaces = ["eth0", "wlan0", "usb0"]
    return interfaces

def get_network_info_enhanced(interface):
    """Улучшенное получение информации о сети с поддержкой Termux"""
    local_ip = None
    local_mac = None
    network_mask = None
    
    try:
        # Способ 1: Через sysfs (стандартный Linux)
        try:
            with open(f"/sys/class/net/{interface}/address", "r") as f:
                local_mac = f.read().strip()
        except:
            pass
        
        # Способ 2: Через ip команду
        result = subprocess.run(
            f"ip -4 addr show {interface} 2>/dev/null",
            shell=True, capture_output=True, text=True
        )
        if result.returncode == 0 and result.stdout:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'inet' in line:
                    parts = line.strip().split()
                    ip_info = parts[1]
                    local_ip = ip_info.split('/')[0]
                    network_mask = int(ip_info.split('/')[1])
                    break
        
        # Способ 3: Для Termux - через ifconfig
        if not local_ip:
            result = subprocess.run(
                f"ifconfig {interface} 2>/dev/null",
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                for line in result.stdout.strip().split('\n'):
                    if 'inet ' in line:
                        parts = line.strip().split()
                        local_ip = parts[1]
                        # Пытаемся получить маску
                        if 'netmask' in parts:
                            mask_idx = parts.index('netmask') + 1
                            if mask_idx < len(parts):
                                mask_hex = parts[mask_idx]
                                # Конвертируем hex маску в CIDR
                                if mask_hex.startswith('0x'):
                                    mask_int = int(mask_hex, 16)
                                    # Подсчет битов в маске
                                    network_mask = bin(mask_int).count('1')
        
        # Способ 4: Для Termux - через ip link
        if not local_mac:
            result = subprocess.run(
                f"ip link show {interface} 2>/dev/null | grep link/ether",
                shell=True, capture_output=True, text=True
            )
            if result.returncode == 0 and result.stdout:
                local_mac = result.stdout.strip().split()[1]
        
        # Способ 5: Резервный - через ipconfig (Android)
        if not local_ip:
            try:
                result = subprocess.run(
                    "ipconfig 2>/dev/null",
                    shell=True, capture_output=True, text=True
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if 'IP Address' in line:
                            local_ip = line.split(':')[-1].strip()
                        elif 'Subnet Mask' in line:
                            mask = line.split(':')[-1].strip()
                            # Конвертируем маску в CIDR
                            mask_parts = mask.split('.')
                            if len(mask_parts) == 4:
                                mask_bin = ''.join([bin(int(x))[2:].zfill(8) for x in mask_parts])
                                network_mask = mask_bin.count('1')
            except:
                pass
        
        return local_ip, local_mac, network_mask
        
    except Exception as e:
        print(f"\033[1;33m[!] Ошибка получения сетевой информации: {str(e)}\033[0m")
        return None, None, None
