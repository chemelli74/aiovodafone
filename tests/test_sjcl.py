"""Tests for SJCL helper and crypto compatibility functions."""

from __future__ import annotations

import base64

import pytest
from Crypto.Cipher import AES

from aiovodafone.exceptions import SJCLError
from aiovodafone.sjcl import SJCL, get_aes_mode, truncate_iv

EXPECTED_NONCE_MAX_LEN = 13


def test_truncate_iv_shortens_to_expected_length() -> None:
    """Ensure CCM IV truncation returns expected nonce length."""
    iv = b"0123456789abcdef"
    result = truncate_iv(iv, ol=128, tlen=64)
    assert len(result) == EXPECTED_NONCE_MAX_LEN


def test_truncate_iv_loop_increments_for_large_output_length() -> None:
    """Ensure truncate loop handles large output lengths correctly."""
    iv = b"0123456789abcdef"
    result = truncate_iv(iv, ol=1 << 24, tlen=64)
    assert len(result) <= EXPECTED_NONCE_MAX_LEN


def test_get_aes_mode_valid() -> None:
    """Ensure valid AES mode names map to pycryptodome constants."""
    assert get_aes_mode("ccm") == AES.MODE_CCM


def test_get_aes_mode_invalid_raises() -> None:
    """Ensure unsupported AES mode names raise SJCLError."""
    with pytest.raises(SJCLError):
        get_aes_mode("invalid")


def test_encrypt_decrypt_roundtrip_ccm() -> None:
    """Ensure SJCL CCM encryption/decryption round-trip works."""
    sjcl = SJCL()
    payload = sjcl.encrypt(b"hello", "passphrase", mode="ccm")
    decrypted = sjcl.decrypt(payload, "passphrase")
    assert decrypted == b"hello"


def test_encrypt_decrypt_roundtrip_gcm() -> None:
    """Ensure SJCL GCM encryption/decryption round-trip works."""
    sjcl = SJCL()
    payload = sjcl.encrypt(b"hello-gcm", "passphrase", mode="gcm", iv_length=12)
    decrypted = sjcl.decrypt(payload, "passphrase")
    assert decrypted == b"hello-gcm"


def test_decrypt_rejects_non_aes_cipher() -> None:
    """Ensure decrypt rejects payloads using non-AES cipher values."""
    data = {
        "cipher": "des",
        "mode": "ccm",
        "ts": 64,
        "adata": "",
        "v": 1,
        "salt": base64.b64encode(b"12345678").decode(),
        "ks": 128,
        "iter": 1000,
        "ct": base64.b64encode(b"abcd").decode(),
        "iv": base64.b64encode(b"123456789012").decode(),
    }
    with pytest.raises(SJCLError, match="only aes cipher supported"):
        SJCL().decrypt(data, "x")


def test_decrypt_rejects_adata() -> None:
    """Ensure decrypt rejects additional authentication data usage."""
    payload = SJCL().encrypt(b"x", "secret")
    payload["adata"] = "not-empty"
    with pytest.raises(SJCLError, match="additional authentication data"):
        SJCL().decrypt(payload, "secret")


def test_decrypt_rejects_version() -> None:
    """Ensure decrypt rejects unsupported SJCL payload versions."""
    payload = SJCL().encrypt(b"x", "secret")
    payload["v"] = 2
    with pytest.raises(SJCLError, match="only version 1"):
        SJCL().decrypt(payload, "secret")


def test_decrypt_rejects_bad_salt_length() -> None:
    """Ensure decrypt validates expected salt byte length."""
    payload = SJCL().encrypt(b"x", "secret")
    payload["salt"] = base64.b64encode(b"short").decode()
    with pytest.raises(SJCLError, match="salt should be"):
        SJCL().decrypt(payload, "secret")


def test_decrypt_rejects_invalid_key_size() -> None:
    """Ensure decrypt validates derived key length settings."""
    payload = SJCL().encrypt(b"x", "secret")
    payload["ks"] = 192
    with pytest.raises(SJCLError, match="key length should be"):
        SJCL().decrypt(payload, "secret")


def test_decrypt_handles_ccm_padding_on_base64_fields() -> None:
    """Ensure decrypt tolerates missing base64 padding in CCM payload fields."""
    payload = SJCL().encrypt(b"pad", "secret")
    payload["salt"] = payload["salt"].rstrip(b"=").decode()
    payload["iv"] = payload["iv"].rstrip(b"=").decode()
    payload["ct"] = payload["ct"].rstrip(b"=").decode()
    assert SJCL().decrypt(payload, "secret") == b"pad"
