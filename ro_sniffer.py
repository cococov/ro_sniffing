#!/usr/bin/env python3
"""
Ragnarok Online (Ragexe.exe) Packet Sniffer

Captura paquetes de red enviados/recibidos por Ragexe.exe y los imprime en consola.
Funciona en Linux (Wine) y Windows.
Requiere permisos de root/admin para capturar paquetes.
"""

import sys
import struct
import time
import argparse
import platform
from datetime import datetime

import psutil
from scapy.all import sniff, TCP, IP, Raw, get_if_list


# Puertos conocidos de Ragnarok Online (pueden variar por servidor)
DEFAULT_RO_PORTS = {6900, 6121, 5121}

# Nombres de paquetes conocidos de RO (header_id -> nombre)
# Referencia: https://github.com/rathena/rathena/blob/master/src/map/packets.hpp
KNOWN_PACKETS = {
    # Login
    0x0064: "LOGIN_REQUEST",
    0x0069: "LOGIN_ACCEPT",
    0x006A: "LOGIN_REFUSE",
    0x0825: "LOGIN_REQUEST_MODERN",
    0x0AC4: "LOGIN_ACCEPT_MODERN",
    0x0B60: "LOGIN_ACCEPT_TW",
    0x0C32: "LOGIN_ACCEPT_ROLA",
    # Char Select
    0x0065: "CHAR_CONNECT",
    0x006B: "CHAR_LIST",
    0x006C: "CHAR_REFUSE",
    0x006D: "CHAR_CREATE_OK",
    0x0066: "CHAR_SELECT",
    0x0067: "CHAR_CREATE",
    0x0068: "CHAR_DELETE",
    0x0071: "CHAR_MAP_INFO",
    # Map Server
    0x0072: "MAP_CONNECT",
    0x0073: "MAP_CONNECT_OK",
    0x007D: "MAP_LOADED",
    0x007E: "MAP_PING_REQ",
    0x007F: "MAP_PING",
    0x0360: "SYNC",
    0x0B1C: "PING_MODERN",
    # GameGuard
    0x09CF: "GAMEGUARD_REQUEST",
    0x09D0: "GAMEGUARD_REPLY",
    # Movimiento
    0x0085: "WALK_REQUEST",
    0x0086: "WALK_OK",
    0x0087: "WALK_MOVE",
    0x0088: "MOVE_NOTIFY",
    # Chat
    0x008C: "CHAT_LOCAL",
    0x008D: "CHAT_LOCAL_RECV",
    0x008E: "CHAT_LOCAL_SEND",
    0x0096: "WHISPER_SEND",
    0x0097: "WHISPER_RECV",
    0x0098: "WHISPER_RESULT",
    0x009A: "BROADCAST",
    0x00C1: "REQUEST_USER_COUNT",
    0x00C2: "USERS_ONLINE",
    # Items
    0x009E: "ITEM_DROP",
    0x009F: "ITEM_PICKUP_REQ",
    0x00A0: "ITEM_PICKUP",
    0x00A2: "ITEM_DROP_REQ",
    0x00AF: "ITEM_DELETE",
    0x01C8: "ITEM_USE",
    0x00A7: "ITEM_USE_REQ",
    # Stats / Status
    0x00B0: "STATUS_PARAM",
    0x00B1: "STATUS_PARAM2",
    0x00BD: "STATUS_POINTS",
    0x00BE: "STATUS_UP_REQ",
    0x00BC: "STATUS_UP_RESULT",
    # Skills
    0x010F: "SKILL_LIST",
    0x0113: "SKILL_USE_ID_REQ",
    0x0116: "SKILL_USE_POS_REQ",
    0x01CD: "SKILL_USE_ID",
    0x07FB: "SKILL_CAST",
    # Items (modern)
    0x07FD: "SPECIAL_ITEM_OBTAIN",
    # NPC
    0x0090: "NPC_CLICK",
    0x00B5: "NPC_NEXT",
    0x00B6: "NPC_CLOSE",
    0x00B8: "NPC_MENU_SELECT",
    0x00B9: "NPC_NEXT_REQ",
    # Equip
    0x00A9: "EQUIP_REQ",
    0x00AA: "EQUIP_RESULT",
    0x00AB: "UNEQUIP_REQ",
    0x00AC: "UNEQUIP_RESULT",
    # Entity
    0x0078: "ENTITY_STANDING",
    0x007B: "ENTITY_MOVING",
    0x0080: "ENTITY_VANISH",
    0x0091: "MAP_CHANGE",
    0x0092: "MAP_CHANGE_SERVER",
    0x09FD: "ACTOR_MOVED",
    0x09FE: "ACTOR_CONNECTED",
    0x09FF: "ACTOR_EXISTS",
    0x01D0: "REVOLVING_ENTITY",
    0x0229: "CHARACTER_STATUS",
    # Status / Buffs
    0x043F: "ACTOR_STATUS_ACTIVE",
    0x0983: "ACTOR_STATUS_ACTIVE2",
    # Emotion / Effect
    0x00C0: "EMOTION",
    0x00BF: "EMOTION_REQ",
    0x019B: "EFFECT",
    # Warp / Respawn
    0x0089: "PLAYER_ACTION_REQ",
    0x008A: "PLAYER_ACTION",
    # Party
    0x00F9: "PARTY_CREATE_REQ",
    0x00FA: "PARTY_CREATE_RESULT",
    0x00FC: "PARTY_INVITE_REQ",
    0x00FD: "PARTY_INVITE_RESULT",
    0x00FE: "PARTY_INVITE_RECV",
    0x0100: "PARTY_LEAVE_REQ",
    0x0101: "PARTY_SETTINGS",
    0x0105: "PARTY_LEAVE",
    0x0107: "PARTY_UPDATE",
    0x0108: "PARTY_MESSAGE_REQ",
    0x0109: "PARTY_MESSAGE",
    # Guild
    0x014D: "GUILD_CHECK",
    0x014E: "GUILD_INFO",
    0x014F: "GUILD_INVITE_REQ",
    0x016B: "GUILD_INVITE_RESULT",
    0x016A: "GUILD_INVITE_RECV",
    # Vending
    0x0130: "VENDING_LIST_REQ",
    0x0131: "VENDING_LIST",
    0x0134: "VENDING_BUY_REQ",
    # Storage
    0x03F0: "STORAGE_OPEN",
    0x00F3: "STORAGE_ADD_REQ",
    0x00F4: "STORAGE_ADD",
    0x00F5: "STORAGE_GET_REQ",
    0x00F6: "STORAGE_GET",
    0x00F7: "STORAGE_CLOSE",
    # Zeny
    0x00B1: "ZENY_UPDATE",
}

# Paquetes con largo variable (header 2 bytes + length 2 bytes + payload)
# Estos paquetes indican su propio largo en los bytes 2-3
VARIABLE_LENGTH_PACKETS = {
    0x0069,  # LOGIN_ACCEPT
    0x0AC4,  # LOGIN_ACCEPT_MODERN (kRO)
    0x0B60,  # LOGIN_ACCEPT_TW (tRO/twRO)
    0x0C32,  # LOGIN_ACCEPT_ROLA
    0x006B,  # CHAR_LIST
    0x008D,  # CHAT_LOCAL_RECV
    0x008E,  # CHAT_LOCAL_SEND
    0x0097,  # WHISPER_RECV
    0x009A,  # BROADCAST
    0x010F,  # SKILL_LIST
    0x0131,  # VENDING_LIST
    0x09CF,  # GAMEGUARD_REQUEST
    0x09FD,  # ACTOR_MOVED
    0x09FE,  # ACTOR_CONNECTED
    0x09FF,  # ACTOR_EXISTS
    0x07FD,  # SPECIAL_ITEM_OBTAIN
}

# Paquetes con largo fijo conocido (header_id -> largo total en bytes)
FIXED_LENGTH_PACKETS = {
    0x00C1: 2,   # REQUEST_USER_COUNT (solo header, sin payload)
    0x00C2: 6,   # USERS_ONLINE (header 2 + uint32 users 4)
    0x0080: 7,   # ENTITY_VANISH
    0x007F: 6,   # MAP_PING
    0x0360: 6,   # SYNC (header 2 + time V 4)
    0x0B1C: 2,   # PING_MODERN (solo header)
    0x09D0: 2,   # GAMEGUARD_REPLY (solo header)
    0x07FB: 25,  # SKILL_CAST
    0x043F: 25,  # ACTOR_STATUS_ACTIVE
    0x0983: 29,  # ACTOR_STATUS_ACTIVE2
    0x01D0: 8,   # REVOLVING_ENTITY (header 2 + a4 + v = 8)
    0x0229: 15,  # CHARACTER_STATUS (header 2 + a4 + v2 + V + C = 15)
    0x00B0: 8,   # STATUS_PARAM
    0x01C8: 15,  # ITEM_USE
}


class Colors:
    """Colores ANSI para la consola."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"
    BG_DARK = "\033[40m"


# Buffer de reassembly TCP por conexion
# Key: (src_ip, src_port, dst_ip, dst_port)
# Value: bytearray
tcp_streams = {}


def find_ragexe_ports():
    """Busca puertos usados por Ragexe.exe (funciona con Wine también).
    Retorna (local_ports, remote_ports) separados.
    """
    local_ports = set()
    remote_ports = set()
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            cmdline = " ".join(proc.info["cmdline"] or []).lower()

            is_ragexe = "ragexe" in name or "ragexe" in cmdline

            if is_ragexe:
                print(f"{Colors.GREEN}[+] Proceso encontrado: {proc.info['name']} "
                      f"(PID: {proc.info['pid']}){Colors.RESET}")
                connections = proc.net_connections()
                for conn in connections:
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        local_ports.add(conn.laddr.port)
                        remote_ports.add(conn.raddr.port)
                        print(f"    {Colors.CYAN}Conexion: {conn.laddr.ip}:{conn.laddr.port} "
                              f"<-> {conn.raddr.ip}:{conn.raddr.port}{Colors.RESET}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return local_ports, remote_ports


def hex_dump(data, bytes_per_line=16):
    """Genera un hex dump formateado de los datos."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {Colors.GRAY}{i:04X}{Colors.RESET}  "
                     f"{hex_part:<{bytes_per_line * 3}}  "
                     f"{Colors.DIM}{ascii_part}{Colors.RESET}")
    return "\n".join(lines)


def parse_server_entries(server_data):
    """Intenta parsear entradas de servidor probando formato moderno (160 bytes) y clasico (32 bytes).
    Retorna lista de servidores o None.
    """
    # Formato moderno: 160 bytes por entrada (con URL)
    # Referencia: https://github.com/SDxBacon/RagnarokOnlinePlayerMonitor
    #   0x00: IP (4 bytes)
    #   0x04: Port (2 bytes)
    #   0x06: Server Name (20 bytes)
    #   0x1A: Player Count (4 bytes, little-endian int32)
    #   0x1E: State/Type (2 bytes)
    #   0x20: Server URL/Hostname (128 bytes, null-terminated)
    MODERN_SIZE = 160
    if len(server_data) >= MODERN_SIZE:
        servers = []
        for i in range(0, len(server_data) - MODERN_SIZE + 1, MODERN_SIZE):
            entry = server_data[i:i + MODERN_SIZE]
            ip_bytes = entry[0:4]
            port = struct.unpack("<H", entry[4:6])[0]
            if port < 1024:
                break
            name = entry[6:26].split(b'\x00')[0].decode("utf-8", errors="replace")
            if not name.strip():
                break
            users = struct.unpack("<I", entry[0x1A:0x1E])[0]
            server_url = entry[0x20:0xA0].split(b'\x00')[0].decode("utf-8", errors="replace")
            servers.append({
                "ip": f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}",
                "port": port,
                "name": name,
                "users": users,
                "url": server_url,
                "maintenance": 0,
                "new": 0,
            })
        if servers:
            return servers

    # Formato clasico rAthena: 32 bytes por entrada
    #   0x00: IP (4 bytes)
    #   0x04: Port (2 bytes)
    #   0x06: Server Name (20 bytes)
    #   0x1A: User Count (2 bytes)
    #   0x1C: Maintenance (2 bytes)
    #   0x1E: New (2 bytes)
    CLASSIC_SIZE = 32
    if len(server_data) >= CLASSIC_SIZE:
        servers = []
        for i in range(0, len(server_data) - CLASSIC_SIZE + 1, CLASSIC_SIZE):
            entry = server_data[i:i + CLASSIC_SIZE]
            ip_bytes = entry[0:4]
            port = struct.unpack("<H", entry[4:6])[0]
            if port < 1024:
                break
            name = entry[6:26].split(b'\x00')[0].decode("latin-1", errors="replace")
            if not name.strip():
                break
            users = struct.unpack("<H", entry[26:28])[0]
            maintenance = struct.unpack("<H", entry[28:30])[0]
            is_new = struct.unpack("<H", entry[30:32])[0]
            servers.append({
                "ip": f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}",
                "port": port,
                "name": name,
                "users": users,
                "maintenance": maintenance,
                "new": is_new,
            })
        if servers:
            return servers

    return None


def parse_login_accept(data):
    """Parsea el paquete LOGIN_ACCEPT (0x0069) para extraer info de servidores y jugadores online."""
    if len(data) < 4:
        return None

    packet_len = struct.unpack("<H", data[2:4])[0]
    if len(data) < packet_len:
        return None  # Paquete incompleto, necesita mas datos

    login_id1 = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0
    account_id = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0

    # Header: 2(header) + 2(len) + 4(loginID1) + 4(accID) + 4(loginID2) + 4(unused)
    #         + 24(lastLoginIP) + 26(lastLoginTime) + 1(sex) = 67 bytes
    HEADER_SIZE = 67
    server_data = data[HEADER_SIZE:packet_len]

    servers = parse_server_entries(server_data)
    if servers is None:
        return None

    return {
        "account_id": account_id,
        "login_id1": login_id1,
        "servers": servers,
        "packet_len": packet_len,
    }


def parse_login_accept_modern(data, entry_size):
    """Parsea LOGIN_ACCEPT moderno (0x0AC4: 160 bytes/entry, 0x0B60: 164 bytes/entry)."""
    if len(data) < 4:
        return None

    packet_len = struct.unpack("<H", data[2:4])[0]
    if len(data) < packet_len:
        return None

    login_id1 = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0
    account_id = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0

    HEADER_SIZE = 67
    server_data = data[HEADER_SIZE:packet_len]

    if len(server_data) < entry_size:
        return None

    servers = []
    for i in range(0, len(server_data) - entry_size + 1, entry_size):
        entry = server_data[i:i + entry_size]
        ip_bytes = entry[0:4]
        port = struct.unpack("<H", entry[4:6])[0]
        if port < 1024:
            break
        name = entry[6:26].split(b'\x00')[0].decode("utf-8", errors="replace")
        if not name.strip():
            break
        # Offset 26: users (uint16 LE), igual que formato clasico 0x0069
        users = struct.unpack("<H", entry[26:28])[0]
        # Offset 28: display/state (uint16), offset 30: property (uint16)
        # Offset 32: URL/hostname (128 bytes) en formatos modernos
        url = ""
        if entry_size >= 160:
            url = entry[32:160].split(b'\x00')[0].decode("utf-8", errors="replace")
        servers.append({
            "ip": f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}",
            "port": port,
            "name": name,
            "users": users,
            "url": url,
            "maintenance": 0,
            "new": 0,
        })

    if not servers:
        return None

    return {
        "account_id": account_id,
        "login_id1": login_id1,
        "servers": servers,
        "packet_len": packet_len,
    }


def parse_login_accept_0c32(data):
    """Parsea LOGIN_ACCEPT 0x0C32 (ROla).
    Header: 2(id) + 2(len) + 4(sessionID) + 4(accountID) + 4(sessionID2)
            + 4(lastLoginIP) + 26(lastLoginTime) + 1(accountSex) + 17(padding) = 64 bytes
    Server entry: 165 bytes (ip:4 + port:2 + name:20 + users:2 + state:2 + property:2 + ip_port:128 + unknown:5)
    """
    if len(data) < 4:
        return None

    packet_len = struct.unpack("<H", data[2:4])[0]
    if len(data) < packet_len:
        return None

    account_id = struct.unpack("<I", data[8:12])[0] if len(data) >= 12 else 0
    login_id1 = struct.unpack("<I", data[4:8])[0] if len(data) >= 8 else 0

    HEADER_SIZE = 64
    ENTRY_SIZE = 165
    server_data = data[HEADER_SIZE:packet_len]

    if len(server_data) < ENTRY_SIZE:
        return None

    servers = []
    for i in range(0, len(server_data) - ENTRY_SIZE + 1, ENTRY_SIZE):
        entry = server_data[i:i + ENTRY_SIZE]
        ip_bytes = entry[0:4]
        port = struct.unpack("<H", entry[4:6])[0]
        if port < 1024:
            break
        name = entry[6:26].split(b'\x00')[0].decode("utf-8", errors="replace")
        if not name.strip():
            break
        users = struct.unpack("<H", entry[26:28])[0]
        state = struct.unpack("<H", entry[28:30])[0]
        prop = struct.unpack("<H", entry[30:32])[0]
        ip_port_str = entry[32:160].split(b'\x00')[0].decode("utf-8", errors="replace")
        servers.append({
            "ip": f"{ip_bytes[0]}.{ip_bytes[1]}.{ip_bytes[2]}.{ip_bytes[3]}",
            "port": port,
            "name": name,
            "users": users,
            "url": ip_port_str,
            "maintenance": state,
            "new": prop,
        })

    if not servers:
        return None

    return {
        "account_id": account_id,
        "login_id1": login_id1,
        "servers": servers,
        "packet_len": packet_len,
    }


OBJECT_TYPES = {
    0: "Jugador",
    1: "NPC",
    5: "Monstruo",
    6: "NPC",
    7: "Pet",
    8: "Homunculus",
}

# Tabla de jobs (parcial, los mas comunes)
JOB_NAMES = {
    0: "Novice", 1: "Swordman", 2: "Mage", 3: "Archer", 4: "Acolyte",
    5: "Merchant", 6: "Thief", 7: "Knight", 8: "Priest", 9: "Wizard",
    10: "Blacksmith", 11: "Hunter", 12: "Assassin", 13: "Knight (Peco)",
    14: "Crusader", 15: "Monk", 16: "Sage", 17: "Rogue", 18: "Alchemist",
    19: "Bard", 20: "Dancer", 21: "Crusader (Peco)", 23: "Super Novice",
    4001: "High Novice", 4002: "High Swordman", 4003: "High Mage",
    4004: "High Archer", 4005: "High Acolyte", 4006: "High Merchant",
    4007: "High Thief", 4008: "Lord Knight", 4009: "High Priest",
    4010: "High Wizard", 4011: "Whitesmith", 4012: "Sniper",
    4013: "Assassin Cross", 4014: "Lord Knight (Peco)", 4015: "Paladin",
    4016: "Champion", 4017: "Professor", 4018: "Stalker",
    4019: "Creator", 4020: "Clown", 4021: "Gypsy",
    4023: "Rune Knight", 4024: "Warlock", 4025: "Ranger",
    4026: "Arch Bishop", 4027: "Mechanic", 4028: "Guillotine Cross",
    4030: "Royal Guard", 4031: "Sorcerer", 4032: "Minstrel",
    4033: "Wanderer", 4034: "Sura", 4035: "Genetic",
    4036: "Shadow Chaser",
    4054: "Rune Knight T", 4055: "Warlock T", 4056: "Ranger T",
    4057: "Arch Bishop T", 4058: "Mechanic T", 4059: "Guillotine Cross T",
    4060: "Royal Guard T", 4061: "Sorcerer T", 4062: "Minstrel T",
    4063: "Wanderer T", 4064: "Sura T", 4065: "Genetic T",
    4066: "Shadow Chaser T",
    4068: "Star Emperor", 4069: "Soul Reaper",
    4070: "Star Emperor 2", 4071: "Soul Reaper 2",
    4073: "Kagerou", 4074: "Oboro", 4075: "Rebellion",
    4076: "Summoner", 4077: "Summoner 2",
    4096: "Dragon Knight", 4097: "Meister", 4098: "Shadow Cross",
    4099: "Arch Mage", 4100: "Cardinal", 4101: "Windhawk",
    4102: "Imperial Guard", 4103: "Biolo", 4104: "Abyss Chaser",
    4105: "Elemental Master", 4106: "Inquisitor", 4107: "Troubadour",
    4108: "Trouvere",
    4109: "Sky Emperor", 4110: "Soul Ascetic", 4111: "Shinkiro",
    4112: "Shiranui", 4113: "Night Watch", 4114: "Spirit Handler",
    4215: "Hyper Novice",
}


def parse_actor_packet(data, header_id):
    """Parsea paquetes de actor 0x09FD (moved), 0x09FE (connected), 0x09FF (exists).
    Extrae nombre, nivel, job, isBoss, HP, etc.
    """
    if len(data) < 20:
        return None

    packet_len = struct.unpack("<H", data[2:4])[0]
    if len(data) < packet_len:
        return None

    object_type = data[4]
    actor_id = struct.unpack("<I", data[5:9])[0]
    char_id = struct.unpack("<I", data[9:13])[0]
    walk_speed = struct.unpack("<H", data[13:15])[0]
    job = struct.unpack("<H", data[23:25])[0]
    hair_style = struct.unpack("<H", data[25:27])[0]

    # Los offsets difieren segun el paquete:
    # 0x09FD tiene tick(V) extra y coords(a6 vs a3), desplaza 7 bytes
    if header_id == 0x09FD:
        # v V v6 a4 a2 v V C2 a6 C2 v2 V2 C v Z*
        guild_id = struct.unpack("<I", data[53:57])[0]
        manner = struct.unpack("<H", data[59:61])[0]
        opt3 = struct.unpack("<I", data[61:65])[0]
        stance = data[65]
        sex = data[66]
        # coords a6 at 67-72
        lv = struct.unpack("<H", data[75:77])[0]
        max_hp = struct.unpack("<I", data[79:83])[0]
        hp = struct.unpack("<I", data[83:87])[0]
        is_boss = data[87]
        opt4 = struct.unpack("<H", data[88:90])[0]
        name = data[90:packet_len].split(b'\x00')[0].decode("utf-8", errors="replace")
    else:
        # 0x09FE / 0x09FF: v7 a4 a2 v V C2 a3 C2/C3 v2 V2 C v Z*
        guild_id = struct.unpack("<I", data[49:53])[0]
        manner = struct.unpack("<H", data[55:57])[0]
        opt3 = struct.unpack("<I", data[57:61])[0]
        stance = data[61]
        sex = data[62]
        # coords a3 at 63-65
        if header_id == 0x09FF:
            # C3 despues de coords (xSize, ySize, state)
            lv = struct.unpack("<H", data[69:71])[0]
            max_hp = struct.unpack("<I", data[73:77])[0]
            hp = struct.unpack("<I", data[77:81])[0]
            is_boss = data[81]
            opt4 = struct.unpack("<H", data[82:84])[0]
            name = data[84:packet_len].split(b'\x00')[0].decode("utf-8", errors="replace")
        else:
            # 0x09FE: C2 despues de coords (xSize, ySize)
            lv = struct.unpack("<H", data[68:70])[0]
            max_hp = struct.unpack("<I", data[72:76])[0]
            hp = struct.unpack("<I", data[76:80])[0]
            is_boss = data[80]
            opt4 = struct.unpack("<H", data[81:83])[0]
            name = data[83:packet_len].split(b'\x00')[0].decode("utf-8", errors="replace")

    return {
        "object_type": object_type,
        "object_type_name": OBJECT_TYPES.get(object_type, "Desconocido"),
        "actor_id": actor_id,
        "char_id": char_id,
        "job": job,
        "job_name": JOB_NAMES.get(job, f"Job {job}"),
        "name": name,
        "lv": lv,
        "sex": "M" if sex == 1 else "F",
        "walk_speed": walk_speed,
        "guild_id": guild_id,
        "manner": manner,
        "opt3": opt3,
        "opt4": opt4,
        "max_hp": max_hp,
        "hp": hp,
        "is_boss": is_boss,
    }


def parse_users_online(data):
    """Parsea el paquete USERS_ONLINE (0x00C2): header(2) + users(uint32 LE, 4 bytes) = 6 bytes."""
    if len(data) < 6:
        return None
    users = struct.unpack("<I", data[2:6])[0]
    return {"users": users}


def process_stream_buffer(stream_key, direction, src_ip, src_port, dst_ip, dst_port):
    """Intenta extraer y procesar paquetes RO completos del buffer de un stream TCP."""
    buf = tcp_streams.get(stream_key)
    if not buf or len(buf) < 2:
        return

    while len(buf) >= 2:
        header_id = struct.unpack("<H", buf[:2])[0]
        packet_name = KNOWN_PACKETS.get(header_id, "UNKNOWN")

        # Determinar largo del paquete
        if header_id in VARIABLE_LENGTH_PACKETS:
            if len(buf) < 4:
                break  # Esperar mas datos para leer el largo
            packet_len = struct.unpack("<H", buf[2:4])[0]
            if packet_len < 4:
                # Largo invalido, descartar 2 bytes y reintentar
                del buf[:2]
                continue
            if len(buf) < packet_len:
                break  # Esperar mas datos
        elif header_id in FIXED_LENGTH_PACKETS:
            packet_len = FIXED_LENGTH_PACKETS[header_id]
            if len(buf) < packet_len:
                break  # Esperar mas datos
        else:
            # Paquete de largo desconocido: usar todo el buffer actual
            packet_len = len(buf)

        # Extraer paquete completo
        packet_data = bytes(buf[:packet_len])
        del buf[:packet_len]

        # Parsear y mostrar
        packet_info = {
            "header_id": header_id,
            "name": packet_name,
            "size": len(packet_data),
            "data": packet_data,
            "direction": direction,
        }

        if header_id == 0x0069:
            login_info = parse_login_accept(packet_data)
            if login_info:
                packet_info["login_info"] = login_info
        elif header_id == 0x0AC4:
            login_info = parse_login_accept_modern(packet_data, entry_size=160)
            if login_info:
                packet_info["login_info"] = login_info
        elif header_id == 0x0B60:
            login_info = parse_login_accept_modern(packet_data, entry_size=164)
            if login_info:
                packet_info["login_info"] = login_info
        elif header_id == 0x0C32:
            login_info = parse_login_accept_0c32(packet_data)
            if login_info:
                packet_info["login_info"] = login_info
        elif header_id in (0x09FD, 0x09FE, 0x09FF):
            actor_info = parse_actor_packet(packet_data, header_id)
            if actor_info:
                packet_info["actor_info"] = actor_info
        elif header_id == 0x00C2:
            users_info = parse_users_online(packet_data)
            if users_info:
                packet_info["users_online"] = users_info

        print_packet(packet_info, src_ip, src_port, dst_ip, dst_port)

        # Para paquetes de largo desconocido, no seguir buscando en el buffer
        if header_id not in VARIABLE_LENGTH_PACKETS and header_id not in FIXED_LENGTH_PACKETS:
            break


def print_packet(packet_info, src_ip, src_port, dst_ip, dst_port):
    """Imprime un paquete de forma legible en consola."""
    direction = packet_info["direction"]
    header_id = packet_info["header_id"]
    name = packet_info["name"]
    size = packet_info["size"]
    data = packet_info["data"]

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if direction == "RECV":
        dir_color = Colors.GREEN
        dir_arrow = "<<<"
    else:
        dir_color = Colors.YELLOW
        dir_arrow = ">>>"

    name_color = Colors.WHITE if name != "UNKNOWN" else Colors.GRAY

    # Header
    print(f"\n{Colors.BOLD}{dir_color}{dir_arrow} [{direction}]{Colors.RESET} "
          f"{Colors.DIM}{timestamp}{Colors.RESET} "
          f"{Colors.CYAN}{src_ip}:{src_port}{Colors.RESET} -> "
          f"{Colors.CYAN}{dst_ip}:{dst_port}{Colors.RESET}")

    print(f"  {Colors.BOLD}Packet:{Colors.RESET} "
          f"{name_color}{name}{Colors.RESET} "
          f"(0x{header_id:04X}) "
          f"{Colors.DIM}[{size} bytes]{Colors.RESET}")

    # Decodificacion especifica de paquetes
    if "login_info" in packet_info:
        login_info = packet_info["login_info"]
        print(f"  {Colors.BOLD}{Colors.MAGENTA}--- Informacion de Servidores ---{Colors.RESET}")
        if login_info["account_id"]:
            print(f"  {Colors.DIM}Account ID: {login_info['account_id']}{Colors.RESET}")
        for srv in login_info["servers"]:
            maint_str = f" {Colors.RED}[MANTENIMIENTO]{Colors.RESET}" if srv["maintenance"] else ""
            new_str = f" {Colors.GREEN}[NUEVO]{Colors.RESET}" if srv["new"] else ""
            url_str = f"\n    {Colors.DIM}URL: {srv['url']}{Colors.RESET}" if srv.get("url") else ""
            print(f"  {Colors.BOLD}{Colors.WHITE}{srv['name']}{Colors.RESET}"
                  f"  {Colors.CYAN}{srv['ip']}:{srv['port']}{Colors.RESET}"
                  f"  {Colors.BOLD}{Colors.GREEN}{srv['users']} jugadores online{Colors.RESET}"
                  f"{maint_str}{new_str}{url_str}")
        print(f"  {Colors.MAGENTA}--------------------------------{Colors.RESET}")

    # Decodificacion: actor (0x09FD/0x09FE/0x09FF)
    if "actor_info" in packet_info:
        a = packet_info["actor_info"]
        is_player = a["object_type"] == 0
        boss_str = ""
        if a["is_boss"]:
            boss_str = f" {Colors.BOLD}{Colors.RED}[GM/BOSS isBoss={a['is_boss']}]{Colors.RESET}"
        hp_str = ""
        if a["max_hp"] != 0xFFFFFFFF:
            hp_str = f"  HP: {a['hp']}/{a['max_hp']}"
        guild_str = ""
        if a["guild_id"]:
            guild_str = f"  Guild: {a['guild_id']}"
        if is_player:
            print(f"  {Colors.BOLD}{Colors.CYAN}--- Jugador ---{Colors.RESET}")
            print(f"  {Colors.BOLD}{Colors.WHITE}{a['name']}{Colors.RESET}"
                  f"  Lv.{a['lv']} {a['job_name']}"
                  f"  ({a['sex']})"
                  f"{hp_str}{guild_str}{boss_str}")
            print(f"  {Colors.CYAN}---------------{Colors.RESET}")
        else:
            print(f"  {Colors.DIM}{a['object_type_name']}: {a['name']}"
                  f"  (ID:{a['actor_id']}){boss_str}{Colors.RESET}")

    # Decodificacion: usuarios online (0x00C2)
    if "users_online" in packet_info:
        users = packet_info["users_online"]["users"]
        print(f"  {Colors.BOLD}{Colors.MAGENTA}--- Usuarios Online ---{Colors.RESET}")
        print(f"  {Colors.BOLD}{Colors.GREEN}{users} jugadores online (total){Colors.RESET}")
        print(f"  {Colors.MAGENTA}-----------------------{Colors.RESET}")

    # Hex dump (limitar a primeros 128 bytes para no saturar la consola)
    display_data = data[:128]
    print(hex_dump(display_data))
    if len(data) > 128:
        print(f"  {Colors.DIM}... ({len(data) - 128} bytes mas){Colors.RESET}")


def packet_callback(packet, local_ports, server_ports, ids_only=False):
    """Callback para cada paquete capturado."""
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    tcp_layer = packet[TCP]

    src_port = tcp_layer.sport
    dst_port = tcp_layer.dport

    # Determinar direccion: server_ports son puertos del servidor RO,
    # local_ports son puertos efimeros del cliente
    if src_port in server_ports:
        direction = "RECV"
    elif dst_port in server_ports:
        direction = "SEND"
    elif dst_port in local_ports:
        direction = "RECV"
    elif src_port in local_ports:
        direction = "SEND"
    else:
        direction = "????"

    stream_key = (ip_layer.src, src_port, ip_layer.dst, dst_port)

    # Limpiar buffer en FIN o RST
    if tcp_layer.flags.F or tcp_layer.flags.R:
        tcp_streams.pop(stream_key, None)
        return

    if not packet.haslayer(Raw):
        return

    raw_data = bytes(packet[Raw].load)

    if ids_only:
        # Modo IDs: imprimir solo el header hex de cada payload TCP recibido
        if len(raw_data) >= 2:
            header_id = struct.unpack("<H", raw_data[:2])[0]
            name = KNOWN_PACKETS.get(header_id, "???")
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            dir_arrow = "<<<" if direction == "RECV" else ">>>"
            dir_color = Colors.GREEN if direction == "RECV" else Colors.YELLOW
            print(f"{Colors.DIM}{timestamp}{Colors.RESET} "
                  f"{dir_color}{dir_arrow}{Colors.RESET} "
                  f"0x{header_id:04X} "
                  f"{Colors.DIM}({name}) "
                  f"[{len(raw_data)} bytes] "
                  f":{src_port}->{dst_port}{Colors.RESET}")
        return

    # Acumular datos en el buffer del stream
    if stream_key not in tcp_streams:
        tcp_streams[stream_key] = bytearray()
    tcp_streams[stream_key].extend(raw_data)

    # Procesar paquetes completos del buffer
    process_stream_buffer(stream_key, direction,
                          ip_layer.src, src_port, ip_layer.dst, dst_port)


def build_bpf_filter(ports):
    """Construye un filtro BPF para los puertos dados."""
    if not ports:
        return "tcp"
    port_filter = " or ".join(f"port {p}" for p in ports)
    return f"tcp and ({port_filter})"


def main():
    parser = argparse.ArgumentParser(description="Ragnarok Online Packet Sniffer")
    parser.add_argument("--ids", action="store_true",
                        help="Modo compacto: solo listar header IDs de los paquetes")
    parser.add_argument("--iface", type=str,
                        help="Interfaz de red a usar (recomendado en Windows)")
    parser.add_argument("--list-ifaces", action="store_true",
                        help="Lista interfaces disponibles y sale")
    parser.add_argument("ports", nargs="*", type=int,
                        help="Puertos personalizados a monitorear")
    args = parser.parse_args()

    if args.list_ifaces:
        print(f"{Colors.BOLD}[*] Interfaces disponibles:{Colors.RESET}")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(0)

    print(f"""
{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════════╗
║     Ragnarok Online Packet Sniffer           ║
║     Ragexe.exe Network Monitor               ║
╚══════════════════════════════════════════════╝{Colors.RESET}
""")

    if args.ids:
        print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Modo IDs: mostrando solo header IDs{Colors.RESET}")

    # Buscar proceso Ragexe.exe
    print(f"{Colors.BOLD}[*] Buscando proceso Ragexe.exe...{Colors.RESET}")
    local_ports, remote_ports = find_ragexe_ports()

    # Siempre incluir puertos por defecto de RO + puertos personalizados
    server_ports = set(DEFAULT_RO_PORTS)
    if args.ports:
        server_ports.update(args.ports)
        print(f"{Colors.GREEN}[+] Puertos personalizados: {set(args.ports)}{Colors.RESET}")

    if remote_ports:
        server_ports.update(remote_ports)
        print(f"{Colors.GREEN}[+] Puertos remotos detectados: {remote_ports}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Puertos locales detectados: {local_ports}{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}[!] Ragexe.exe no encontrado o sin conexiones activas.{Colors.RESET}")

    # monitor_ports = todos los puertos (locales + remotos + defaults) para el BPF filter
    monitor_ports = server_ports | local_ports
    print(f"{Colors.DIM}[*] Puertos monitoreados: {monitor_ports}{Colors.RESET}")

    # Construir filtro
    bpf_filter = build_bpf_filter(monitor_ports)
    print(f"{Colors.BOLD}[*] Filtro BPF: {bpf_filter}{Colors.RESET}")
    if args.iface:
        print(f"{Colors.BOLD}[*] Interfaz: {args.iface}{Colors.RESET}")
    print(f"{Colors.BOLD}[*] Capturando paquetes... (Ctrl+C para detener){Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 60}{Colors.RESET}")

    ids_only = args.ids

    try:
        sniff(
            filter=bpf_filter,
            prn=lambda pkt: packet_callback(pkt, local_ports, server_ports, ids_only),
            iface=args.iface,
            store=False,
        )
    except PermissionError:
        print(f"\n{Colors.RED}[!] Error: Se requieren permisos elevados para capturar paquetes.{Colors.RESET}")
        if platform.system().lower() == "windows":
            print(f"{Colors.YELLOW}    Ejecuta PowerShell/CMD como Administrador y vuelve a correr el script.{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}    Ejecuta: sudo python3 {sys.argv[0]}{Colors.RESET}")
        sys.exit(1)
    except OSError as err:
        print(f"\n{Colors.RED}[!] Error de captura: {err}{Colors.RESET}")
        if platform.system().lower() == "windows":
            print(f"{Colors.YELLOW}    Verifica que Npcap esté instalado y prueba con --list-ifaces / --iface.{Colors.RESET}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n{Colors.BOLD}[*] Sniffer detenido.{Colors.RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
