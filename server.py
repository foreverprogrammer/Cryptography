"""
服务端（1 个，支持多客户端）：
- 管理客户端连接
- 用户名/密码认证（bcrypt 哈希存储）
- 接收客户端 RSA 公钥，用 RSA-OAEP 加密“房间 AES 密钥”发回给该客户端
- 转发客户端发来的 AES-GCM 密文消息（不解密：实现“端到端”风格的密文转发）

核心知识点标注：
1) bcrypt 哈希存储密码：自动加盐（salt），抗彩虹表与暴力破解更强
2) RSA-OAEP：安全地把 AES 会话密钥发给每个客户端（避免明文传输）
3) 服务端不持有 RSA 私钥，不解密聊天内容，仅转发密文（服务器被动监听风险降低）
"""

import json
import os
import socket
import threading
import struct
import time
from typing import Dict, Tuple

import bcrypt

from crypto_utils import generate_aes256_key, rsa_encrypt_oaep, b64e, b64d

HOST = "0.0.0.0"
PORT = 5000

USER_DB_FILE = "user_db.json"  # bcrypt 哈希存储（示例：本地文件）
LOCK = threading.Lock()


def send_frame(conn: socket.socket, obj: dict):
    """
    发送 length-prefixed JSON 帧：
    - 先发 4 字节大端长度，再发 JSON bytes
    优点：解决 TCP 粘包/拆包问题
    """
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
    """
    接收 length-prefixed JSON 帧
    """
    header = recv_exact(conn, 4)
    (length,) = struct.unpack("!I", header)
    payload = recv_exact(conn, length)
    return json.loads(payload.decode("utf-8"))


def load_user_db() -> Dict[str, str]:
    """
    读取用户库：{username: bcrypt_hash_str}
    """
    if not os.path.exists(USER_DB_FILE):
        return {}
    with open(USER_DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_user_db(db: Dict[str, str]):
    with open(USER_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)


def ensure_default_users():
    """
    为了便于测试：首次运行自动创建两个用户（alice / bob），密码都是 password123
    bcrypt 自动加盐：每次 hash 都不同，但都能正确校验
    """
    db = load_user_db()
    changed = False

    defaults = {
        "alice": "esther",
        "bob": "19951218",
    }

    for u, pw in defaults.items():
        if u not in db:
            pw_hash = bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt(rounds=12))
            db[u] = pw_hash.decode("utf-8")
            changed = True

    if changed:
        save_user_db(db)


def verify_login(username: str, password: str) -> bool:
    """
    bcrypt 校验：hash 内含 salt，无需额外存盐
    """
    db = load_user_db()
    if username not in db:
        return False
    stored = db[username].encode("utf-8")
    return bcrypt.checkpw(password.encode("utf-8"), stored)


# 服务器状态：在线客户端
clients: Dict[str, Tuple[socket.socket, Tuple[str, int]]] = {}
# 房间 AES 密钥（全体共享，用于端到端加密聊天）
ROOM_KEY = generate_aes256_key()


def broadcast(sender: str, msg: dict):
    """
    广播给所有在线用户（包括 sender 自己也可以收到；这里默认不发给自己）
    注意：服务端不解密，只转发密文
    """
    with LOCK:
        targets = [(u, c) for u, (c, _) in clients.items() if u != sender]

    for u, conn in targets:
        try:
            send_frame(conn, msg)
        except Exception:
            # 发送失败：对端可能断开，稍后由线程清理
            pass


def handle_client(conn: socket.socket, addr):
    username = None
    try:
        # 1) 接收 login
        hello = recv_frame(conn)
        if hello.get("type") != "login":
            send_frame(conn, {"type": "error", "message": "Expected login"})
            return

        username = hello.get("username", "")
        password = hello.get("password", "")
        if not (isinstance(username, str) and isinstance(password, str)):
            send_frame(conn, {"type": "error", "message": "Invalid login payload"})
            return

        if not verify_login(username, password):
            send_frame(conn, {"type": "login_result", "ok": False, "message": "Authentication failed"})
            return

        # 2) 登录成功，要求客户端发送 RSA 公钥（用于加密分发 ROOM_KEY）
        send_frame(conn, {"type": "login_result", "ok": True, "message": "Login ok. Send RSA public key."})

        pub_msg = recv_frame(conn)
        if pub_msg.get("type") != "client_pubkey":
            send_frame(conn, {"type": "error", "message": "Expected client_pubkey"})
            return

        public_key_pem_b64 = pub_msg.get("public_key_pem_b64", "")
        try:
            public_key_pem = b64d(public_key_pem_b64)
        except Exception:
            send_frame(conn, {"type": "error", "message": "Invalid public key encoding"})
            return

        # 3) RSA-OAEP 加密房间 AES 密钥，发给客户端
        #    知识点：ROOM_KEY 不以明文发送；仅客户端私钥可解开
        try:
            enc_room_key = rsa_encrypt_oaep(public_key_pem, ROOM_KEY)
        except Exception as e:
            send_frame(conn, {"type": "error", "message": f"RSA encrypt failed: {e}"})
            return

        send_frame(conn, {"type": "room_key", "enc_room_key_b64": b64e(enc_room_key)})

        # 4) 将客户端加入在线列表
        with LOCK:
            clients[username] = (conn, addr)

        # 通知其他人：有用户上线（可选，明文系统消息）
        broadcast(
            sender=username,
            msg={"type": "system", "message": f"{username} joined the chat.", "ts": time.time()},
        )

        # 5) 循环接收聊天密文并转发
        while True:
            frame = recv_frame(conn)
            t = frame.get("type")

            if t == "chat":
                # 仅做最小字段校验
                # 注意：ciphertext 与 nonce 是 base64 字符串，服务端不解密
                out = {
                    "type": "chat",
                    "from": username,
                    "nonce_b64": frame.get("nonce_b64"),
                    "ciphertext_b64": frame.get("ciphertext_b64"),
                    "ts": time.time(),
                }
                print(f"[FORWARD] from={username} nonce_b64={frame.get('nonce_b64')[:16]}... "
                      f"ciphertext_b64={frame.get('ciphertext_b64')[:24]}...")

                broadcast(sender=username, msg=out)
            elif t == "logout":
                break
            else:
                send_frame(conn, {"type": "error", "message": "Unknown message type"})
    except (ConnectionError, OSError):
        pass
    except Exception as e:
        try:
            send_frame(conn, {"type": "error", "message": f"Server exception: {e}"})
        except Exception:
            pass
    finally:
        # 清理客户端
        if username:
            with LOCK:
                if username in clients:
                    del clients[username]
            try:
                broadcast(
                    sender=username,
                    msg={"type": "system", "message": f"{username} left the chat.", "ts": time.time()},
                )
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


def main():
    ensure_default_users()
    print(f"[+] Server starting on {HOST}:{PORT}")
    print("[+] Default users: alice / bob")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(100)

    try:
        while True:
            conn, addr = s.accept()
            th = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            th.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutting down...")
    finally:
        s.close()


if __name__ == "__main__":
    main()
