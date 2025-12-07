import socket
import threading
import secrets
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


APP_TITLE = "Secure P2P Chat — RSA + AES-256-GCM (Final Simple Version)"
BUFFER_SIZE = 8192


def safe_print(*args, **kwargs):
    print(*args, flush=True, **kwargs)


# ---------------- SECURE CHAT CLASS ----------------
class SecureChat:
    def __init__(self, private_key, public_key, passphrase: str):
        self.private_key = private_key
        self.public_key = public_key
        self.passphrase = passphrase
        self.peer_public_key: Optional[rsa.RSAPublicKey] = None
        self.aes_key: Optional[bytes] = None

    # --- helpers for length-prefixed blocks (for pubkeys etc.) ---
    @staticmethod
    def _recv_exact(conn, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _send_block(self, conn, payload: bytes):
        length = len(payload).to_bytes(4, "big")
        conn.sendall(length + payload)

    def _recv_block(self, conn) -> bytes:
        length = int.from_bytes(self._recv_exact(conn, 4), "big")
        if length <= 0 or length > 100_000:
            raise ValueError("Invalid block length")
        return self._recv_exact(conn, length)

    # --- crypto ---
    def rsa_encrypt(self, data: bytes) -> bytes:
        return self.peer_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def rsa_decrypt(self, data: bytes) -> bytes:
        return self.private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def aes_encrypt(self, msg: str) -> bytes:
        nonce = secrets.token_bytes(12)
        ct = AESGCM(self.aes_key).encrypt(nonce, msg.encode(), None)
        return nonce + ct

    def aes_decrypt(self, data: bytes) -> str:
        nonce = data[:12]
        ct = data[12:]
        return AESGCM(self.aes_key).decrypt(nonce, ct, None).decode()

    def _hash(self, challenge: bytes) -> bytes:
        h = hashes.Hash(hashes.SHA256())
        h.update(challenge + self.passphrase.encode())
        return h.finalize()[:16]

    # --- HANDSHAKE (server/client) ---
    def perform_handshake(self, conn, is_server: bool) -> bool:
        # 1) Exchange public keys
        try:
            my_pub = self.public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            self._send_block(conn, my_pub)
            peer_pub = self._recv_block(conn)
            self.peer_public_key = serialization.load_der_public_key(peer_pub)
        except Exception as e:
            safe_print(f"[!] Key exchange failed: {e}")
            return False

        # 2) Passphrase authentication
        try:
            if is_server:
                challenge = secrets.token_bytes(32)
                conn.sendall(b"AUTH:" + self.rsa_encrypt(challenge))

                reply = conn.recv(BUFFER_SIZE)
                if not reply.startswith(b"AUTH:"):
                    safe_print("[!] Invalid AUTH reply.")
                    return False
                proof = self.rsa_decrypt(reply[5:])
                if proof != self._hash(challenge):
                    safe_print("[!] Wrong passphrase!")
                    return False
            else:
                msg = conn.recv(BUFFER_SIZE)
                if not msg.startswith(b"AUTH:"):
                    safe_print("[!] Invalid AUTH challenge.")
                    return False
                challenge = self.rsa_decrypt(msg[5:])
                conn.sendall(b"AUTH:" + self.rsa_encrypt(self._hash(challenge)))
        except Exception as e:
            safe_print(f"[!] Authentication failed: {e}")
            return False

        # 3) AES key setup
        try:
            if is_server:
                self.aes_key = secrets.token_bytes(32)
                conn.sendall(b"KEY:" + self.rsa_encrypt(self.aes_key))
            else:
                msg = conn.recv(BUFFER_SIZE)
                if not msg.startswith(b"KEY:"):
                    safe_print("[!] Invalid KEY message.")
                    return False
                self.aes_key = self.rsa_decrypt(msg[4:])
        except Exception as e:
            safe_print(f"[!] AES key exchange failed: {e}")
            return False

        safe_print("\n[+] SECURE CONNECTION ESTABLISHED!\n")
        return True


# ---------------- CHAT LOOPS ----------------
def recv_loop(conn, chat: SecureChat):
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            # Ignore handshake markers if any slipped through
            if data.startswith(b"AUTH:") or data.startswith(b"KEY:"):
                continue
            try:
                msg = chat.aes_decrypt(data)
            except Exception:
                safe_print("[!] Failed to decrypt incoming message.")
                continue
            safe_print(f"[Friend] {msg}")
    except Exception:
        pass
    safe_print("\n[!] Disconnected.")
    os._exit(0)


def send_loop(conn, chat: SecureChat):
    while True:
        try:
            msg = input("> ").strip()
        except EOFError:
            break

        if msg.lower() in {"exit", "/q"}:
            safe_print("[*] Closing connection.")
            conn.close()
            os._exit(0)

        if not msg:
            continue

        try:
            enc = chat.aes_encrypt(msg)
            conn.sendall(enc)
        except Exception as e:
            safe_print(f"[!] Send failed: {e}")
            conn.close()
            os._exit(0)


# ---------------- HOST / CLIENT MODES ----------------
def run_host(chat: SecureChat):
    while True:
        p = input("Host port (default 5555): ").strip()
        if p == "":
            port = 5555
            break
        if p.isdigit() and 1024 <= int(p) <= 65535:
            port = int(p)
            break
        safe_print("Port must be 1024–65535 or empty for default.")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        s.bind(("0.0.0.0", port))
        s.listen(1)
    except Exception as e:
        safe_print(f"[!] Host error: {e}")
        return

    safe_print(f"\n[Host] Waiting for connection on port {port}...")
    conn, addr = s.accept()
    safe_print(f"[Host] Incoming connection from {addr[0]}:{addr[1]}")

    if not chat.perform_handshake(conn, is_server=True):
        conn.close()
        return

    threading.Thread(target=recv_loop, args=(conn, chat), daemon=True).start()
    send_loop(conn, chat)


def run_client(chat: SecureChat):
    ip = input("Host IP (default 127.0.0.1): ").strip() or "127.0.0.1"

    while True:
        p = input("Host port (default 5555): ").strip()
        if p == "":
            port = 5555
            break
        if p.isdigit() and 1024 <= int(p) <= 65535:
            port = int(p)
            break
        safe_print("Port must be 1024–65535 or empty for default.")

    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        safe_print(f"\n[Client] Connecting to {ip}:{port}...")
        conn.connect((ip, port))
    except Exception as e:
        safe_print(f"[!] Connect error: {e}")
        return

    if not chat.perform_handshake(conn, is_server=False):
        conn.close()
        return

    threading.Thread(target=recv_loop, args=(conn, chat), daemon=True).start()
    send_loop(conn, chat)


# ---------------- MAIN ----------------
def main():
    safe_print(APP_TITLE)
    safe_print("=" * 60)

    # Generate keys
    safe_print("Generating 2048-bit RSA key pair...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    safe_print("Done.\n")

    # Shared passphrase
    passphrase = ""
    while not passphrase.strip():
        passphrase = input("Shared passphrase (must match on both sides): ").strip()
        if not passphrase:
            safe_print("Passphrase cannot be empty.\n")

    chat = SecureChat(private_key, public_key, passphrase)

    # Host or client?
    mode = ""
    while mode not in {"h", "c"}:
        mode = input("\nHost or connect? (h/c): ").strip().lower()

    if mode == "h":
        run_host(chat)
    else:
        run_client(chat)


if __name__ == "__main__":
    main()
