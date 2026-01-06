import subprocess
import os
import json
import base64
import random
import argparse
from pathlib import Path

# =====================
# НАСТРОЙКИ
# =====================

WG_INTERFACE = "wg0"
WG_DIR = "./clients"            # куда сохраgjxtveнять конфиги
SERVER_PUBLIC_KEY = "k6pj+BXTWet6eN9WpANyIFDKYyID0PYp6cokrToev0Q="
SERVER_ENDPOINT = "79.132.143.147:51820"
SERVER_DNS = "1.1.1.1"
TXT_DIR = "./keys_txt"         # куда сохранять .txt в формате vpn://<base64>
CLIENTS_DB = Path(WG_DIR) / "clients.json"

BASE_IP = "10.0.0."              # пул IP
START_IP = 2                     # первый IP для клиентов


# =====================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =====================

def run(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True).decode().strip()
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {cmd}\n{e}")


def ensure_dir():
    Path(WG_DIR).mkdir(parents=True, exist_ok=True)
    Path(TXT_DIR).mkdir(parents=True, exist_ok=True)


def load_clients():
    try:
        if CLIENTS_DB.exists():
            return json.loads(CLIENTS_DB.read_text())
        return {}
    except Exception:
        return {}


def save_clients(data):
    CLIENTS_DB.write_text(json.dumps(data, ensure_ascii=False, indent=2))


# =====================
# ГЕНЕРАЦИЯ КЛЮЧЕЙ
# =====================

def generate_keys():
    # Generate private key
    try:
        private_key = subprocess.check_output(["wg", "genkey"]).decode().strip()
    except Exception as e:
        raise RuntimeError(f"Failed to generate private key: {e}")

    # Generate public key from private key using stdin (safe)
    try:
        proc = subprocess.run(["wg", "pubkey"], input=private_key.encode(), capture_output=True)
        public_key = proc.stdout.decode().strip()
        if not public_key:
            raise RuntimeError(proc.stderr.decode().strip())
    except Exception as e:
        raise RuntimeError(f"Failed to generate public key: {e}")

    return private_key, public_key


def ensure_wg_up():
    try:
        run(f"wg show {WG_INTERFACE}")
    except Exception:
        try:
            run(f"wg-quick up {WG_INTERFACE}")
        except Exception as e:
            print(f"Не удалось поднять интерфейс {WG_INTERFACE}: {e}")


def get_default_interface():
    try:
        out = run("ip route show default")
        # example: 'default via 192.0.2.1 dev eth0 proto dhcp metric 100'
        parts = out.split()
        if 'dev' in parts:
            idx = parts.index('dev')
            return parts[idx + 1]
    except Exception:
        pass
    return None


def enable_ipv4_forwarding():
    try:
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    except Exception:
        try:
            run('sysctl -w net.ipv4.ip_forward=1')
        except Exception as e:
            print(f"Не удалось включить ip_forward: {e}")


def setup_nat_once():
    """Добавляет одну MASQUERADE для подсети и правила FORWARD (идемпотентно)."""
    ext_if = get_default_interface()
    if not ext_if:
        print("Не удалось определить внешний интерфейс; настройте NAT вручную")
        return
    enable_ipv4_forwarding()
    subnet = f"{BASE_IP}0/24"
    try:
        run(f"iptables -t nat -C POSTROUTING -s {subnet} -o {ext_if} -j MASQUERADE")
    except Exception:
        try:
            run(f"iptables -t nat -A POSTROUTING -s {subnet} -o {ext_if} -j MASQUERADE")
            print(f"Добавлен MASQUERADE для {subnet} -> {ext_if}")
        except Exception as e:
            print(f"Не удалось добавить MASQUERADE: {e}")
    try:
        run(f"iptables -C FORWARD -i {WG_INTERFACE} -j ACCEPT")
    except Exception:
        try:
            run(f"iptables -A FORWARD -i {WG_INTERFACE} -j ACCEPT")
        except Exception as e:
            print(f"Не удалось добавить правило FORWARD (out): {e}")
    try:
        run(f"iptables -C FORWARD -o {WG_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT")
    except Exception:
        try:
            run(f"iptables -A FORWARD -o {WG_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT")
        except Exception as e:
            print(f"Не удалось добавить правило FORWARD (in): {e}")


# =====================
# РАБОТА С WIREGUARD
# =====================

def add_peer(public_key: str, ip: str):
    try:
        ensure_wg_up()
        # Ensure peer has exactly the client's IP allowed (replace previous allowed-ips)
        run(f"wg set {WG_INTERFACE} peer {public_key} allowed-ips {ip}/32")
    except Exception as e:
        print(f"Не удалось добавить/обновить peer: {e}")


def remove_peer(public_key: str):
    try:
        run(f"wg set {WG_INTERFACE} peer {public_key} remove")
    except Exception as e:
        print(f"Не удалось удалить peer: {e}")


# =====================
# БЛОКИРОВКА / РАЗБЛОКИРОВКА
# =====================

def block_ip(ip: str):
    try:
        run(f"iptables -A FORWARD -s {ip} -j DROP")
    except Exception as e:
        print(f"Не удалось заблокировать IP {ip}: {e}")


def unblock_ip(ip: str):
    try:
        run(f"iptables -D FORWARD -s {ip} -j DROP")
    except Exception as e:
        print(f"Не удалось разблокировать IP {ip}: {e}")


# =====================
# ГЕНЕРАЦИЯ КОНФИГА
# =====================

def generate_client_config(
    client_name: str,
    private_key: str,
    ip: str
):
    # Generate preshared key for extra security
    try:
        preshared = run("wg genpsk")
    except Exception:
        preshared = base64.b64encode(os.urandom(32)).decode()

    dns_field = SERVER_DNS if SERVER_DNS else "1.1.1.1"

    # Minimal standard WireGuard client config (no custom fields)
    config = f"""[Interface]
PrivateKey = {private_key}
Address = {ip}/32
DNS = {dns_field}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
PresharedKey = {preshared}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {SERVER_ENDPOINT}
PersistentKeepalive = 25
"""

    path = Path(WG_DIR) / f"{client_name}.conf"
    path.write_text(config)
    return path, config


def save_txt_uri(client_name: str, config_text: str):
    # Сохраняем конфиг в .txt в том же формате, что и в примере
    path = Path(TXT_DIR) / f"{client_name}.txt"
    path.write_text(config_text)
    return path


# =====================
# СОЗДАНИЕ ПОЛЬЗОВАТЕЛЯ
# =====================

def create_user(client_name: str, ip_index: int):
    ensure_dir()

    ip = f"{BASE_IP}{ip_index}"
    private_key, public_key = generate_keys()
    add_peer(public_key, ip)
    config_path, config_text = generate_client_config(
        client_name,
        private_key,
        ip
    )

    txt_path = save_txt_uri(client_name, config_text)

    # Сохраняем запись в clients.json
    clients = load_clients()
    clients[client_name] = {
        'ip': ip,
        'public_key': public_key,
        'config_path': str(config_path),
        'txt_path': str(txt_path),
        'frozen': False
    }
    save_clients(clients)

    print("✅ Пользователь создан")
    print("IP:", ip)
    print("Public key:", public_key)
    print("Config:", config_path)
    print("TXT:", txt_path)


def repair_all_clients():
    """Применяет правильные allowed-ips и NAT/forward для всех клиентов из clients.json"""
    clients = load_clients()
    if not clients:
        print("Нет клиентов в clients.json")
        return
    for name, info in clients.items():
        pub = info.get('public_key')
        ip = info.get('ip')
        if not pub or not ip:
            print(f"Пропускаю {name}, нет pub/ip")
            continue
        try:
            ensure_wg_up()
            run(f"wg set {WG_INTERFACE} peer {pub} allowed-ips {ip}/32")
            print(f"Обновлён {name}: {pub} -> {ip}")
        except Exception as e:
            print(f"Ошибка при ремонте {name}: {e}")


def freeze_peer_by_pubkey(pubkey: str):
    clients = load_clients()
    for name, info in clients.items():
        if info.get('public_key') == pubkey:
            ip = info.get('ip')
            block_ip(ip)
            # NAT для подсети настройте один раз через 'setup-nat'
            info['frozen'] = True
            save_clients(clients)
            print(f"{name} ({ip}) заморожен")
            return True
    print("Клиент с таким публичным ключом не найден")
    return False


def unfreeze_peer_by_pubkey(pubkey: str):
    clients = load_clients()
    for name, info in clients.items():
        if info.get('public_key') == pubkey:
            ip = info.get('ip')
            unblock_ip(ip)
            info['frozen'] = False
            save_clients(clients)
            print(f"{name} ({ip}) разморожен")
            return True
    print("Клиент с таким публичным ключом не найден")
    return False


def freeze_peer_by_name(name: str):
    clients = load_clients()
    info = clients.get(name)
    if not info:
        print("Клиент не найден")
        return False
    block_ip(info['ip'])
    info['frozen'] = True
    save_clients(clients)
    print(f"{name} заморожен")
    return True


def unfreeze_peer_by_name(name: str):
    clients = load_clients()
    info = clients.get(name)
    if not info:
        print("Клиент не найден")
        return False
    unblock_ip(info['ip'])
    info['frozen'] = False
    save_clients(clients)
    print(f"{name} разморожен")
    return True


# =====================
# ПРИМЕР ИСПОЛЬЗОВАНИЯ
# =====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Manage VPN clients')
    sub = parser.add_subparsers(dest='cmd')

    create = sub.add_parser('create')
    create.add_argument('name')
    create.add_argument('--ip-index', type=int, default=START_IP)

    freeze = sub.add_parser('freeze')
    freeze_group = freeze.add_mutually_exclusive_group(required=True)
    freeze_group.add_argument('--pubkey')
    freeze_group.add_argument('--name')

    unfreeze = sub.add_parser('unfreeze')
    unfreeze_group = unfreeze.add_mutually_exclusive_group(required=True)
    unfreeze_group.add_argument('--pubkey')
    unfreeze_group.add_argument('--name')

    repair = sub.add_parser('repair')
    setup = sub.add_parser('setup-nat')

    args = parser.parse_args()

    if args.cmd == 'create':
        create_user(args.name, args.ip_index)
    elif args.cmd == 'repair':
        repair_all_clients()
    elif args.cmd == 'setup-nat':
        setup_nat_once()
    elif args.cmd == 'freeze':
        if args.pubkey:
            freeze_peer_by_pubkey(args.pubkey)
        else:
            freeze_peer_by_name(args.name)
    elif args.cmd == 'unfreeze':
        if args.pubkey:
            unfreeze_peer_by_pubkey(args.pubkey)
        else:
            unfreeze_peer_by_name(args.name)
    else:
        parser.print_help()
