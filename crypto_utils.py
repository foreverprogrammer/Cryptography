# crypto_utils.py
"""
加密工具模块：集中封装密码学原语，便于审计与复用。

核心知识点：
1) RSA-2048：非对称加密。用于“加密分发 AES 会话密钥”，避免 AES 密钥明文传输。
2) OAEP（SHA-256）：RSA 安全填充方案，避免裸 RSA 的确定性问题与多种攻击。
3) AES-256-GCM：认证加密（AEAD）。同时提供机密性 + 完整性/认证：
   - ciphertext 内含 GCM 的认证标签（tag），解密时会自动校验；若被篡改会抛异常。
4) nonce/IV：GCM 必须保证“同一密钥下 nonce 不重复”，否则安全性会崩溃。
"""

import os
import base64
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# -------------------------
# Base64 helpers (网络传输友好)
# -------------------------
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("utf-8"))


# -------------------------
# RSA utilities
# -------------------------
@dataclass
class RSAKeyPair:
    """
    RSA 密钥对（2048 位）：
    - private_key：客户端保存私钥，用于解密服务端发来的“加密后的 AES 会话密钥”
    - public_key_pem：发送给服务端，用于加密该客户端的 AES 会话密钥
    """
    private_key: rsa.RSAPrivateKey
    public_key_pem: bytes


def generate_rsa_keypair(bits: int = 2048) -> RSAKeyPair:
    """
    生成 RSA 密钥对（默认 RSA-2048）。

    知识点：密钥长度越长越安全，但更慢；课程通常要求 RSA-2048。
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKeyPair(private_key=private_key, public_key_pem=public_pem)


def load_public_key_from_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


def rsa_encrypt_oaep(public_key_pem: bytes, plaintext: bytes) -> bytes:
    """
    RSA-OAEP 加密（SHA-256）。

    知识点：OAEP 是推荐填充方式，避免裸 RSA 的确定性与可塑性风险。
    """
    pub = load_public_key_from_pem(public_key_pem)
    return pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt_oaep(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """
    RSA-OAEP 解密（SHA-256）。
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# -------------------------
# AES-GCM utilities
# -------------------------
def generate_aes256_key() -> bytes:
    """
    生成 AES-256 密钥（32 字节）。
    """
    return os.urandom(32)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """
    AES-256-GCM 加密：
    - 返回 (nonce, ciphertext_with_tag)
    - cryptography 的 AESGCM.encrypt 输出 = ciphertext || tag（tag 自动附在末尾）

    知识点：
    - GCM 是 AEAD：提供机密性 + 完整性
    - nonce 建议 12 字节；同一 key 下 nonce 必须“绝不重复”
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    nonce = os.urandom(12)  # 96-bit nonce (推荐长度)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)  # ct includes tag
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: bytes = b"") -> bytes:
    """
    AES-256-GCM 解密（带认证）：
    - 若 ciphertext 或 aad 被篡改，AESGCM.decrypt 会抛异常（InvalidTag）
    """
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
