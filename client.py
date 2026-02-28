"""
客户端功能：
- 用户登录（用户名/密码）
- 生成 RSA-2048 密钥对，把公钥发给服务端
- 用私钥解密服务端发来的“房间 AES-256 密钥”（RSA-OAEP）
- 使用 AES-256-GCM 加密消息并发送；接收密文后解密并显示

核心知识点：
1) RSA 用于密钥交换：对称密钥更高效，但必须安全分发；用 RSA 加密 AES key 解决此问题。
2) AES-GCM 是认证加密：解密时验证 tag，防止密文被篡改/伪造。
3) AAD（附加认证数据）：这里将 sender 绑定进认证（防止“改 from 字段”）
"""

import json
import socket
import struct
import threading
import sys
import getpass
import time

from cryptography.exceptions import InvalidTag

from crypto_utils import (
    generate_rsa_keypair,
    rsa_decrypt_oaep,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    b64e,
    b64d,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5000


def send_frame(conn: socket.socket, obj: dict):
    data = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    header = struct.pack("!I", len(data))
    conn.sendall(header + data)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(conn: socket.socket) -> dict:
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    payload = recv_exact(conn, length)
    return json.loads(payload.decode("utf-8"))


class ClientState:
    def __init__(self):
        self.username = None
        self.room_key = None  # AES-256 key (32 bytes)


def receiver_loop(conn: socket.socket, state: ClientState):
    """
    接收线程：持续接收服务端转发的消息。
    """
    try:
        while True:
            msg = recv_frame(conn)
            t = msg.get("type")

            if t == "system":
                print(f"\n[SYSTEM] {msg.get('message')}")
                print("> ", end="", flush=True)

            elif t == "chat":
                sender = msg.get("from", "")
                nonce = b64d(msg.get("nonce_b64", ""))
                ciphertext = b64d(msg.get("ciphertext_b64", ""))

                # AAD 绑定 sender，防止攻击者篡改 from 字段而不被发现
                aad = sender.encode("utf-8")

                try:
                    plaintext = aes_gcm_decrypt(state.room_key, nonce, ciphertext, aad=aad)
                    print(f"\n[{sender}] {plaintext.decode('utf-8', errors='replace')}")
                except InvalidTag:
                    # 知识点：tag 校验失败说明消息被篡改/伪造/密钥不一致
                    print(f"\n[!] Message authentication failed (InvalidTag) from {sender}")
                except Exception as e:
                    print(f"\n[!] Decrypt error from {sender}: {e}")

                print("> ", end="", flush=True)

            elif t == "error":
                print(f"\n[SERVER ERROR] {msg.get('message')}")
                print("> ", end="", flush=True)

            else:
                # 忽略未知类型
                pass
    except (ConnectionError, OSError):
        print("\n[!] Disconnected from server.")
    except Exception as e:
        print(f"\n[!] Receiver exception: {e}")


def main():
    host = SERVER_HOST
    port = SERVER_PORT

    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    state = ClientState()

    # 1) 连接
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        conn.connect((host, port))
    except Exception as e:
        print(f"[!] Connect failed: {e}")
        return

    try:
        # 2) 登录
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        state.username = username

        send_frame(conn, {"type": "login", "username": username, "password": password})
        res = recv_frame(conn)

        if res.get("type") != "login_result" or not res.get("ok"):
            print(f"[!] Login failed: {res.get('message')}")
            return

        print("[+] Login OK")

        # 3) 生成 RSA 密钥对，并发送公钥
        kp = generate_rsa_keypair(bits=2048)
        send_frame(conn, {"type": "client_pubkey", "public_key_pem_b64": b64e(kp.public_key_pem)})

        # 4) 接收并解密房间 AES key
        key_msg = recv_frame(conn)
        if key_msg.get("type") != "room_key":
            print("[!] Did not receive room key")
            return

        enc_room_key = b64d(key_msg["enc_room_key_b64"])
        try:
            room_key = rsa_decrypt_oaep(kp.private_key, enc_room_key)
        except Exception as e:
            print(f"[!] RSA decrypt room key failed: {e}")
            return

        if len(room_key) != 32:
            print("[!] Invalid room key length")
            return

        state.room_key = room_key
        print("[+] Room key established (AES-256) via RSA-OAEP")

        # 5) 启动接收线程
        th = threading.Thread(target=receiver_loop, args=(conn, state), daemon=True)
        th.start()

        print("Type messages to chat. Type /quit to exit.")
        while True:
            text = input("> ")
            if text.strip() == "/quit":
                send_frame(conn, {"type": "logout"})
                break

            # AAD 绑定 sender
            aad = state.username.encode("utf-8")
            try:
                nonce, ciphertext = aes_gcm_encrypt(state.room_key, text.encode("utf-8"), aad=aad)
            except Exception as e:
                print(f"[!] Encrypt failed: {e}")
                continue

            send_frame(
                conn,
                {
                    "type": "chat",
                    "nonce_b64": b64e(nonce),
                    "ciphertext_b64": b64e(ciphertext),
                    "ts": time.time(),
                },
            )

    except KeyboardInterrupt:
        try:
            send_frame(conn, {"type": "logout"})
        except Exception:
            pass
    except Exception as e:
        print(f"[!] Client exception: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
