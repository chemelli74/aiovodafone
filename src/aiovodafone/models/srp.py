"""Implementation of Technicolor's custom modification of SRP."""

import hashlib
import os

# SRP-6 constants from the router's implementation
GEN = 2
K = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16,
)
C = int("05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16)
U = "4a76a9a2402bdd18123389b72ebbda50a30f65aedb90d7273130edea4b29cc4c"


def _sha256_hex(data: bytes) -> str:
    """Calculate SHA256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def _sha256_bytes(data: bytes) -> bytes:
    """Calculate SHA256 hash and return as bytes."""
    return hashlib.sha256(data).digest()


def _int_to_bytes(n: int, length: int = 256) -> bytes:
    """Convert integer to bytes with specified length.

    Truncates to length if the integer is larger.
    """
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    if len(n_bytes) > length:
        n_bytes = n_bytes[1:]
    return n_bytes


def generate_client_public() -> tuple[int, int]:
    """Generate client's private and public values for SRP.

    Returns:
        tuple of (private_value F, public_value D)

    """
    # Generate random 8 bytes for F
    rand_bytes = os.urandom(8)
    f_private = int.from_bytes(rand_bytes, byteorder="big")

    # Calculate D = GEN^F mod K
    d_public = pow(GEN, f_private, K)

    return f_private, d_public


def calculate_session_key(
    f_private: int,
    d_public: int,
    salt: str,
    server_public: str,
    # username: str,
    password: str,
) -> tuple[str, str, str]:
    """Calculate session key and authentication proofs.

    Args:
        f_private: Client's private value F
        d_public: Client's public value D
        salt: Salt received from server (hex string)
        server_public: Server's public value B (hex string)
        username: User's username
        password: User's password

    Returns:
        tuple of (client_proof M, verification v, session_key_hash)

    """
    username = "vodafone"

    # Parse server public key B
    b_int = int(server_public, 16)

    # Convert D and B to bytes (256 bytes max)
    d_bytes = _int_to_bytes(d_public, 256)
    b_bytes = _int_to_bytes(b_int, 256)

    # Calculate h = SHA256(D || B)
    h_bytes = _sha256_bytes(d_bytes + b_bytes)
    h_int = int.from_bytes(h_bytes, byteorder="big")

    # Calculate n = SHA256(salt + SHA256(username + ":" + password))
    password_hash = _sha256_bytes(f"{username}:{password}".encode())
    n_input = bytes.fromhex(salt + password_hash.hex())
    n_bytes = _sha256_bytes(n_input)
    n_int = int.from_bytes(n_bytes, byteorder="big")

    # Calculate a = (C * GEN^n) mod K
    a_int = (C * pow(GEN, n_int, K)) % K

    # Calculate b = (h * n + F) mod K
    b_value = (h_int * n_int + f_private) % K

    # Calculate session key: g = (B - a)^b mod K
    g_int = pow((b_int - a_int) % K, b_value, K)

    # Convert g to hex string (with even length)
    g_hex = f"{g_int:x}"
    if len(g_hex) % 2 == 1:
        g_hex = "0" + g_hex

    # Calculate session key hash B_hash = SHA256(g)
    g_bytes = bytes.fromhex(g_hex)
    b_hash = _sha256_hex(g_bytes)

    # Calculate client proof
    d_hex = f"{d_public:x}"
    if len(d_hex) % 2 == 1:
        d_hex = "0" + d_hex

    username_hash = _sha256_hex(username.encode())

    y_input = bytes.fromhex(U + username_hash + salt + d_hex + server_public + b_hash)
    y = _sha256_hex(y_input)

    # Calculate verification value
    v_input = bytes.fromhex(d_hex + y + b_hash)
    v = _sha256_hex(v_input)

    return y, v, b_hash
