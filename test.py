import subprocess
import json
import os
from pathlib import Path
import argparse
import base64

WG_INTERFACE = "wg0"
WG_DIR = "./clients"
CLIENTS_DB = Path(WG_DIR) / "clients.json"

SERVER_PUBLIC_KEY = "k6pj+BXTWet6eN9WpANyIFDKYyID0PYp6cokrToev0Q="
SERVER_ENDPOINT = "79.132.143.147:51820"
SERVER_DNS = "1.1.1.1"

BASE_IP = "10.0.0."
START_IP = 2


# ---------------- UTILS ----------------

def run(cmd):
    return subprocess.check_output(cmd, shell=True).decode().strip()


def ensure_dirs():
    Path(WG_DIR).mkdir(exist_ok=True)


def load_clients():
    if CLIENTS_DB.exists():
        return json.loads(CLIENTS_DB.read_text())
    return {}


def save_clients(data):
    CLIENTS_DB.write_text(json.dumps(data, indent=2))


# ---------------- KEYS ----------------

def generate_keys():
    private_key = run("wg genkey")
    public_key = run(f"echo {private_key} | wg pubkey")
    preshared = run("wg genpsk")
    return private_key, public_key, preshared


# ---------------- WG ----------------

def add_peer(pubkey, ip):
    run(f"wg set {WG_INTERFACE} peer {pubkey} allowed-ips {ip}/32")


# ---------------- CONFIG ----------------

def generate_client_conf(name, private, psk, ip):
    conf = f"""[Interface]
PrivateKey = {private}
Address = {ip}/32
DNS = {SERVER_DNS}

[Peer]
PublicKey = {SERVER_PUBLIC_KEY}
PresharedKey = {psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {SERVER_ENDPOINT}
PersistentKeepalive = 25
"""
    path = Path(WG_DIR) / f"{name}.conf"
    path.write_text(conf)
    return path


# ---------------- CREATE USER ----------------

def create_user(name, ip_index):
    ensure_dirs()
    clients = load_clients()

    ip = f"{BASE_IP}{ip_index}"
    private, public, psk = generate_keys()

    add_peer(public, ip)
    conf_path = generate_client_conf(name, private, psk, ip)

    clients[name] = {
        "ip": ip,
        "public_key": public,
        "private_key": private,
        "config": str(conf_path)
    }

    save_clients(clients)

    print("✅ Клиент создан")
    print("IP:", ip)
    print("Public:", public)
    print("Config:", conf_path)


# ---------------- CLI ----------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    c = sub.add_parser("create")
    c.add_argument("name")
    c.add_argument("--ip", type=int, default=START_IP)

    args = parser.parse_args()

    if args.cmd == "create":
        create_user(args.name, args.ip)
    else:
        parser.print_help()
