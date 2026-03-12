#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════╗
║         P2P ENCRYPTED MESSENGER  v1.0             ║
║   End-to-end encrypted • Up to 4 peers • LAN/WAN  ║
╚═══════════════════════════════════════════════════╝

USAGE:
  Host (first person):  python p2p_messenger.py --host
  Join (other people):  python p2p_messenger.py --join <HOST_IP>

REQUIREMENTS:
  pip install cryptography

HOW IT WORKS:
  • Each peer generates an RSA keypair on startup
  • A shared AES-256 session key is negotiated via RSA (OAEP)
  • All chat messages are AES-256-GCM encrypted
  • The host acts as a relay hub for up to 4 peers
  • Messages are broadcast to all connected peers
"""

import argparse
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime

# ── dependency check ────────────────────────────────────────────────────────
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("\n[!] Missing dependency. Please run:\n    pip install cryptography\n")
    sys.exit(1)

# ── constants ────────────────────────────────────────────────────────────────
PORT        = 55000
MAX_PEERS   = 4          # host + 3 joiners = 4 total
BUF_SIZE    = 65536
DELIMITER   = b"\x00ENDMSG\x00"   # frame delimiter


# ════════════════════════════════════════════════════════════════════════════
#  CRYPTO HELPERS
# ════════════════════════════════════════════════════════════════════════════

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    return private_key, private_key.public_key()


def export_public_key(pub_key) -> bytes:
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def import_public_key(pem_bytes):
    return serialization.load_pem_public_key(pem_bytes, backend=default_backend())


def rsa_encrypt(pub_key, data: bytes) -> bytes:
    return pub_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(priv_key, ciphertext: bytes) -> bytes:
    return priv_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Returns nonce + ciphertext."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def aes_decrypt(key: bytes, payload: bytes) -> bytes:
    """Expects nonce (12 bytes) + ciphertext."""
    nonce, ct = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


# ════════════════════════════════════════════════════════════════════════════
#  FRAMING  (length-prefix + delimiter so we can split TCP stream)
# ════════════════════════════════════════════════════════════════════════════

def send_frame(sock: socket.socket, data: bytes):
    frame = len(data).to_bytes(4, "big") + data + DELIMITER
    sock.sendall(frame)


def recv_frame(sock: socket.socket) -> bytes:
    """Block until a full frame arrives."""
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed")
    length = int.from_bytes(raw_len, "big")
    data = _recv_exact(sock, length)
    delim = _recv_exact(sock, len(DELIMITER))
    if delim != DELIMITER:
        raise ValueError("Frame delimiter mismatch")
    return data


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


# ════════════════════════════════════════════════════════════════════════════
#  SHARED PEER STATE
# ════════════════════════════════════════════════════════════════════════════

class PeerState:
    def __init__(self, nickname: str):
        self.nickname = nickname
        self.priv_key, self.pub_key = generate_rsa_keypair()
        self.session_key: bytes | None = None   # AES-256 (32 bytes)
        self.peers: dict[str, socket.socket] = {}   # nickname → socket
        self.lock = threading.Lock()
        self.running = True


# ════════════════════════════════════════════════════════════════════════════
#  PROTOCOL MESSAGES  (JSON envelope, then optional binary payload)
# ════════════════════════════════════════════════════════════════════════════
# Every frame = JSON header (UTF-8) + b"\x1E" + binary payload (may be empty)

SEP = b"\x1e"   # ASCII Record Separator


def pack_msg(header: dict, payload: bytes = b"") -> bytes:
    return json.dumps(header).encode() + SEP + payload


def unpack_msg(frame: bytes) -> tuple[dict, bytes]:
    idx = frame.index(SEP)
    header = json.loads(frame[:idx].decode())
    payload = frame[idx + 1:]
    return header, payload


# ════════════════════════════════════════════════════════════════════════════
#  DISPLAY
# ════════════════════════════════════════════════════════════════════════════

COLORS = {
    "system": "\033[33m",    # yellow
    "me":     "\033[32m",    # green
    "peer1":  "\033[36m",    # cyan
    "peer2":  "\033[35m",    # magenta
    "peer3":  "\033[34m",    # blue
    "reset":  "\033[0m",
}

_peer_color_map: dict[str, str] = {}
_color_pool = ["peer1", "peer2", "peer3"]
_color_lock = threading.Lock()


def peer_color(nick: str) -> str:
    with _color_lock:
        if nick not in _peer_color_map and _color_pool:
            _peer_color_map[nick] = _color_pool.pop(0)
        return COLORS.get(_peer_color_map.get(nick, "peer1"), "")


def sys_print(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\r{COLORS['system']}[{ts}] *** {msg}{COLORS['reset']}")
    print("> ", end="", flush=True)


def chat_print(sender: str, msg: str, is_me=False):
    ts = datetime.now().strftime("%H:%M:%S")
    col = COLORS["me"] if is_me else peer_color(sender)
    tag = "you" if is_me else sender
    print(f"\r{col}[{ts}] {tag}: {msg}{COLORS['reset']}")
    print("> ", end="", flush=True)


# ════════════════════════════════════════════════════════════════════════════
#  KEY EXCHANGE  (host side per-connection)
# ════════════════════════════════════════════════════════════════════════════

def host_handshake(state: PeerState, conn: socket.socket) -> str:
    """
    1. Receive joiner's public key + nickname
    2. Send host's public key + nickname
    3. Generate session key, RSA-encrypt it for joiner, send
    4. Joiner sends back an ACK encrypted with session key
    Returns joiner's nickname.
    """
    # Step 1 – receive joiner identity
    frame = recv_frame(conn)
    hdr, payload = unpack_msg(frame)
    assert hdr["type"] == "HELLO"
    joiner_nick = hdr["nickname"]
    joiner_pub  = import_public_key(payload)

    # Step 2 – send host identity
    send_frame(conn, pack_msg(
        {"type": "HELLO", "nickname": state.nickname},
        export_public_key(state.pub_key),
    ))

    # Step 3 – generate / reuse session key and send it encrypted
    with state.lock:
        if state.session_key is None:
            state.session_key = os.urandom(32)
        sk = state.session_key

    encrypted_sk = rsa_encrypt(joiner_pub, sk)
    send_frame(conn, pack_msg({"type": "SESSION_KEY"}, encrypted_sk))

    # Step 4 – wait for ACK
    frame = recv_frame(conn)
    hdr, payload = unpack_msg(frame)
    assert hdr["type"] == "ACK"
    ack_text = aes_decrypt(sk, payload).decode()
    assert ack_text == "READY"

    return joiner_nick


def joiner_handshake(state: PeerState, conn: socket.socket) -> str:
    """
    1. Send our public key + nickname
    2. Receive host's public key + nickname
    3. Receive RSA-encrypted session key, decrypt with our private key
    4. Send ACK
    Returns host's nickname.
    """
    # Step 1
    send_frame(conn, pack_msg(
        {"type": "HELLO", "nickname": state.nickname},
        export_public_key(state.pub_key),
    ))

    # Step 2
    frame = recv_frame(conn)
    hdr, _ = unpack_msg(frame)
    assert hdr["type"] == "HELLO"
    host_nick = hdr["nickname"]

    # Step 3
    frame = recv_frame(conn)
    hdr, payload = unpack_msg(frame)
    assert hdr["type"] == "SESSION_KEY"
    sk = rsa_decrypt(state.priv_key, payload)
    with state.lock:
        state.session_key = sk

    # Step 4
    send_frame(conn, pack_msg({"type": "ACK"}, aes_encrypt(sk, b"READY")))

    return host_nick


# ════════════════════════════════════════════════════════════════════════════
#  RECEIVE LOOP  (one thread per peer socket)
# ════════════════════════════════════════════════════════════════════════════

def receive_loop(state: PeerState, conn: socket.socket, peer_nick: str, is_host: bool):
    """
    Listens for encrypted chat frames.
    If we are the host we also relay the message to all *other* peers.
    """
    try:
        while state.running:
            frame = recv_frame(conn)
            hdr, payload = unpack_msg(frame)

            if hdr["type"] == "CHAT":
                plaintext = aes_decrypt(state.session_key, payload).decode()
                chat_print(peer_nick, plaintext)

                # host relays to everyone else
                if is_host:
                    relay_frame = pack_msg(
                        {"type": "CHAT", "from": peer_nick},
                        payload,   # already encrypted with shared key
                    )
                    with state.lock:
                        for nick, s in list(state.peers.items()):
                            if nick != peer_nick:
                                try:
                                    send_frame(s, relay_frame)
                                except Exception:
                                    pass

            elif hdr["type"] == "RELAY":
                # joiner receives a relayed message from host
                sender = hdr.get("from", "?")
                plaintext = aes_decrypt(state.session_key, payload).decode()
                chat_print(sender, plaintext)

            elif hdr["type"] == "PEER_JOINED":
                sys_print(f"{hdr['nickname']} joined the chat")

            elif hdr["type"] == "PEER_LEFT":
                sys_print(f"{hdr['nickname']} left the chat")

    except (ConnectionError, ValueError, OSError):
        pass
    finally:
        with state.lock:
            state.peers.pop(peer_nick, None)
        sys_print(f"{peer_nick} disconnected")
        try:
            conn.close()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
#  SEND HELPERS
# ════════════════════════════════════════════════════════════════════════════

def broadcast(state: PeerState, text: str, is_host: bool):
    """Encrypt and send a chat message to all connected peers."""
    if not state.session_key:
        sys_print("No session key yet – waiting for peers to connect.")
        return
    enc = aes_encrypt(state.session_key, text.encode())
    frame = pack_msg({"type": "CHAT", "from": state.nickname}, enc)
    with state.lock:
        dead = []
        for nick, s in list(state.peers.items()):
            try:
                send_frame(s, frame)
            except Exception:
                dead.append(nick)
        for nick in dead:
            state.peers.pop(nick, None)


def notify_peers(state: PeerState, event: str, nick: str):
    frame = pack_msg({"type": event, "nickname": nick})
    with state.lock:
        for s in list(state.peers.values()):
            try:
                send_frame(s, frame)
            except Exception:
                pass


# ════════════════════════════════════════════════════════════════════════════
#  HOST MODE
# ════════════════════════════════════════════════════════════════════════════

def run_host(state: PeerState):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen(MAX_PEERS - 1)

    # Print local IPs so others know where to connect
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    print(f"""
╔══════════════════════════════════════════════╗
║   P2P ENCRYPTED MESSENGER  –  HOST MODE      ║
╠══════════════════════════════════════════════╣
║  Your nickname : {state.nickname:<28}║
║  Listening on  : {local_ip}:{PORT:<21}║
║  Max peers     : {MAX_PEERS - 1} joiners                    ║
╠══════════════════════════════════════════════╣
║  Others run:                                 ║
║  python p2p_messenger.py --join {local_ip:<14}║
╚══════════════════════════════════════════════╝
Type a message and press Enter to send.
Type /quit to exit.
""")

    def accept_loop():
        while state.running:
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
                threading.Thread(
                    target=_handle_new_peer, args=(state, conn, addr),
                    daemon=True,
                ).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_new_peer(state, conn, addr):
        try:
            with state.lock:
                if len(state.peers) >= MAX_PEERS - 1:
                    conn.close()
                    return

            nick = host_handshake(state, conn)
            with state.lock:
                state.peers[nick] = conn

            sys_print(f"{nick} joined! ({addr[0]}) — {len(state.peers)}/{MAX_PEERS-1} slots used")
            notify_peers(state, "PEER_JOINED", nick)

            threading.Thread(
                target=receive_loop, args=(state, conn, nick, True),
                daemon=True,
            ).start()
        except Exception as e:
            sys_print(f"Handshake failed from {addr[0]}: {e}")
            conn.close()

    threading.Thread(target=accept_loop, daemon=True).start()

    # ── input loop ──────────────────────────────────────────────────────────
    try:
        while state.running:
            try:
                text = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not text:
                continue
            if text.lower() == "/quit":
                break
            if text.startswith("/peers"):
                with state.lock:
                    nicks = list(state.peers.keys())
                sys_print("Connected peers: " + (", ".join(nicks) if nicks else "none"))
                continue
            broadcast(state, text, is_host=True)
            chat_print(state.nickname, text, is_me=True)
    finally:
        state.running = False
        server.close()
        sys_print("Host shut down.")


# ════════════════════════════════════════════════════════════════════════════
#  JOINER MODE
# ════════════════════════════════════════════════════════════════════════════

def run_joiner(state: PeerState, host_ip: str):
    print(f"""
╔══════════════════════════════════════════════╗
║   P2P ENCRYPTED MESSENGER  –  JOIN MODE      ║
╠══════════════════════════════════════════════╣
║  Your nickname : {state.nickname:<28}║
║  Connecting to : {host_ip}:{PORT:<21}║
╚══════════════════════════════════════════════╝
Connecting…""")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(10)
    try:
        conn.connect((host_ip, PORT))
    except (ConnectionRefusedError, socket.timeout) as e:
        print(f"[!] Could not connect to {host_ip}:{PORT} — {e}")
        sys.exit(1)
    conn.settimeout(None)

    host_nick = joiner_handshake(state, conn)

    with state.lock:
        state.peers[host_nick] = conn

    sys_print(f"Connected! Session key exchanged with {host_nick}. Channel is encrypted 🔒")
    print("Type a message and press Enter to send.\nType /quit to exit.\n")

    # receive thread
    threading.Thread(
        target=receive_loop, args=(state, conn, host_nick, False),
        daemon=True,
    ).start()

    # ── input loop ──────────────────────────────────────────────────────────
    try:
        while state.running:
            try:
                text = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if not text:
                continue
            if text.lower() == "/quit":
                break
            if text.startswith("/peers"):
                with state.lock:
                    nicks = list(state.peers.keys())
                sys_print("Connected peers: " + (", ".join(nicks) if nicks else "none"))
                continue
            broadcast(state, text, is_host=False)
            chat_print(state.nickname, text, is_me=True)
    finally:
        state.running = False
        conn.close()
        sys_print("Disconnected.")


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

def get_nickname() -> str:
    default = os.environ.get("USER") or os.environ.get("USERNAME") or "user"
    try:
        nick = input(f"Enter your nickname [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        nick = ""
    return nick if nick else default


def main():
    parser = argparse.ArgumentParser(
        description="P2P Encrypted Messenger",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Host:   python p2p_messenger.py --host
  Join:   python p2p_messenger.py --join 192.168.1.42

Commands inside the chat:
  /peers  – list connected peers
  /quit   – exit
        """,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--host", action="store_true", help="Start as host/relay")
    group.add_argument("--join", metavar="HOST_IP", help="Join an existing host")
    args = parser.parse_args()

    print("\n  P2P Encrypted Messenger  |  AES-256-GCM + RSA-2048\n")
    nickname = get_nickname()
    state = PeerState(nickname)

    if args.host:
        run_host(state)
    else:
        run_joiner(state, args.join)


if __name__ == "__main__":
    main()
