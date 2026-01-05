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
WG_DIR = "./clients"            # куда сохранять конфиги
SERVER_PUBLIC_KEY = "PASTE_SERVER_PUBLIC_KEY_HERE"
SERVER_ENDPOINT = "1.2.3.4:51820"
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
    private_key = run("wg genkey")
    # wg pubkey expects the private key on stdin; echoing it is fine for shell
    public_key = run(f"echo {private_key} | wg pubkey")
    return private_key, public_key


# =====================
# РАБОТА С WIREGUARD
# =====================

def add_peer(public_key: str, ip: str):
    try:
        run(f"wg set {WG_INTERFACE} peer {public_key} allowed-ips {ip}/32")
    except Exception as e:
        print(f"Не удалось добавить peer: {e}")


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
        # fallback: random 32 bytes base64
        preshared = base64.b64encode(os.urandom(32)).decode()

    # Additional metadata fields (matching provided template)
    J = random.randint(1, 10)
    Jmin = random.randint(5, 15)
    Jmax = random.randint(30, 80)
    S1 = random.randint(50, 150)
    S2 = random.randint(100, 200)
    H1 = random.randint(1_000_000_000, 2_000_000_000)
    H2 = random.randint(1_000_000, 20_000_000)
    H3 = random.randint(1, 999_999_999)
    H4 = random.randint(1, 999_999_999)

    dns_field = f"{SERVER_DNS}, 1.0.0.1" if SERVER_DNS else "1.1.1.1, 1.0.0.1"

    config = f"""[Interface]
Address = {ip}/32
DNS = {dns_field}
PrivateKey = {private_key}
J = {J}
Jmin = {Jmin}
Jmax = {Jmax}
S1 = {S1}
S2 = {S2}
H1 = {H1}
H2 = {H2}
H3 = {H3}
H4 = {H4}

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
        'private_key': private_key,
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


def freeze_peer_by_pubkey(pubkey: str):
    clients = load_clients()
    for name, info in clients.items():
        if info.get('public_key') == pubkey:
            ip = info.get('ip')
            block_ip(ip)
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

    args = parser.parse_args()

    if args.cmd == 'create':
        create_user(args.name, args.ip_index)
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
