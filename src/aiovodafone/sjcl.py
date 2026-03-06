"""Decrypt and encrypt messages compatible to the "SJCL" message format.

Credits to https://github.com/berlincode/sjcl
"""

import base64
from typing import Any

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from .exceptions import SJCLError

# Default tag length for different AES modes
DEFAULT_TLEN = {AES.MODE_CCM: 64, AES.MODE_GCM: 128}


def truncate_iv(iv: bytes, ol: int, tlen: int) -> bytes:
    """Truncate IV according to SJCL's CCM implementation."""
    ivl = len(iv)
    ol = (ol - tlen) // 8

    # "compute the length of the length"
    iv_len = 2
    min_len = 4
    while (iv_len < min_len) and (ol >> (8 * iv_len)) > 0:
        iv_len += 1
    iv_len = max(iv_len, 15 - ivl)

    return iv[: (15 - iv_len)]


def get_aes_mode(mode: str) -> int:
    """Return pycrypto's AES mode, raise exception if not supported."""
    aes_mode_attr = f"MODE_{mode.upper()}"
    try:
        aes_mode = getattr(AES, aes_mode_attr)
    except AttributeError as exp:
        raise SJCLError(
            f"Pycrypto/pycryptodome does not seem to support {aes_mode_attr}. "
            "If you use pycrypto, you need a version >= 2.7a1 (or a special branch)."
        ) from exp
    return aes_mode


class SJCL:
    """SJCL decryption/encryption class."""

    def __init__(self) -> None:
        """Initialize SJCL decryption/encryption object."""
        self.salt_size = 8  # bytes

    def decrypt(self, data: dict[str, Any], passphrase: str) -> bytes:
        """Decrypt SJCL formatted data with given passphrase."""
        if data["cipher"] != "aes":
            raise SJCLError("only aes cipher supported")

        aes_mode = get_aes_mode(data["mode"])
        tlen = data["ts"]

        if data["adata"] != "":
            raise SJCLError("additional authentication data not equal ''")

        if data["v"] != 1:
            raise SJCLError("only version 1 is currently supported")

        # Fix padding
        if aes_mode == AES.MODE_CCM and len(data["salt"]) % 4:
            # not a multiple of 4, add padding:
            data["salt"] += "=" * (4 - len(data["salt"]) % 4)
        salt = base64.b64decode(data["salt"])

        if len(salt) != self.salt_size:
            raise SJCLError(f"salt should be {self.salt_size} bytes long")

        dk_len = data["ks"] // 8
        if dk_len not in {16, 32}:
            raise SJCLError("key length should be 16 bytes or 32 bytes")
        key = PBKDF2(
            passphrase, salt, count=data["iter"], dkLen=dk_len, hmac_hash_module=SHA256
        )
        if aes_mode == AES.MODE_CCM:
            # Fix padding
            if len(data["iv"]) % 4:
                # not a multiple of 4, add padding:
                data["iv"] += "=" * (4 - len(data["iv"]) % 4)
            if len(data["ct"]) % 4:
                # not a multiple of 4, add padding:
                data["ct"] += "=" * (4 - len(data["ct"]) % 4)

        ciphertext = base64.b64decode(data["ct"])
        iv = base64.b64decode(data["iv"])

        if aes_mode == AES.MODE_CCM:
            nonce = truncate_iv(iv, len(ciphertext) * 8, data["ts"])
        else:
            nonce = iv

        # split tag from ciphertext (tag was simply appended to ciphertext)
        mac = ciphertext[-(data["ts"] // 8) :]
        ciphertext = ciphertext[: -(data["ts"] // 8)]
        cipher = AES.new(key, aes_mode, nonce, mac_len=tlen // 8)
        plaintext = cipher.decrypt(ciphertext)

        cipher.verify(mac)

        return plaintext

    def encrypt(  # noqa: PLR0913
        self,
        plaintext: bytes,
        passphrase: str,
        mode: str = "ccm",
        count: int = 10000,
        dk_len: int = 16,
        iv_length: int = 16,
        salt: bytes | None = None,
        use_bytes: bool | None = True,
    ) -> dict[str, Any]:
        """Encrypt plaintext with given passphrase and return SJCL formatted data."""
        salt_was_generated = False
        aes_mode = get_aes_mode(mode)
        tlen = DEFAULT_TLEN[aes_mode]
        iv = get_random_bytes(iv_length)

        if salt is None:
            salt = get_random_bytes(self.salt_size)
            salt_was_generated = True

        key = PBKDF2(
            passphrase, salt, count=count, dkLen=dk_len, hmac_hash_module=SHA256
        )

        if aes_mode == AES.MODE_CCM:
            nonce = truncate_iv(iv, len(plaintext) * 8, tlen)
        else:
            nonce = iv

        cipher = AES.new(key, aes_mode, nonce, mac_len=tlen // 8)

        ciphertext = cipher.encrypt(plaintext)
        mac = cipher.digest()

        ciphertext = ciphertext + mac

        salt_out = (
            base64.b64encode(salt)
            if use_bytes
            else base64.b64encode(salt).decode("utf-8")
        )
        iv_out = (
            base64.b64encode(iv) if use_bytes else base64.b64encode(iv).decode("utf-8")
        )
        ct_out = (
            base64.b64encode(ciphertext)
            if use_bytes
            else base64.b64encode(ciphertext).decode("utf-8")
        )

        if salt_was_generated:
            return {
                "salt": salt_out,
                "iter": count,
                "ks": dk_len * 8,
                "ct": ct_out,
                "iv": iv_out,
                "cipher": "aes",
                "mode": mode,
                "adata": "",
                "v": 1,
                "ts": tlen,
            }

        return {
            "iv": iv_out,
            "v": 1,
            "iter": count,
            "ks": dk_len * 8,
            "ts": tlen,
            "mode": mode,
            "adata": "",
            "cipher": "aes",
            "ct": ct_out,
        }
