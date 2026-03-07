"""Fixture-based tests for SJCL encryption/decryption compatibility."""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

import aiovodafone.sjcl as sjcl_mod
from aiovodafone.exceptions import SJCLError
from aiovodafone.models.sercomm import VodafoneStationSercommApi
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeSession

if TYPE_CHECKING:
    from yarl import URL


SJCL_FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures", "sjcl")
EXPECTED_NONCE_MAX_LEN = 13


@pytest.fixture(name="sjcl_fixture_path")
def fixture_sjcl_fixture_path(sjcl_fixture_name: str) -> Path:
    """Return the path of the selected router SJCL fixture file."""
    return SJCL_FIXTURES_DIR.joinpath(f"{sjcl_fixture_name}.json")


@pytest.fixture(name="sjcl_fixture")
def fixture_sjcl_fixture(sjcl_fixture_path: Path) -> dict[str, Any]:
    """Load and return the selected router SJCL fixture content."""
    return json.loads(sjcl_fixture_path.read_text(encoding="utf-8"))


def _normalize_encrypted_payload(encrypted_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize SJCL encrypted payload to JSON-compatible types."""
    normalized = encrypted_data.copy()
    for field in ("salt", "ct", "iv"):
        value = normalized[field]
        if isinstance(value, bytes):
            normalized[field] = value.decode("utf-8")
    return normalized


def _normalize_plain_payload(
    plaintext: str | bytes | bytearray | memoryview,
) -> dict[str, str]:
    """Normalize decrypted JSON payload to a flat string dictionary."""
    raw_text = (
        bytes(plaintext).decode("utf-8")
        if isinstance(plaintext, (bytes, bytearray, memoryview))
        else plaintext
    )

    try:
        decoded = json.loads(raw_text)
    except json.JSONDecodeError:
        # UltraHub fixture payload is URL-encoded key/value data.
        parsed_qsl = cast(
            "list[tuple[str, str]]",
            urllib.parse.parse_qsl(raw_text, keep_blank_values=True),
        )
        return {str(k): str(v) for k, v in parsed_qsl}

    if isinstance(decoded, dict):
        return {str(k): str(v) for k, v in decoded.items()}
    if isinstance(decoded, list):
        flattened: dict[str, str] = {}
        for entry in decoded:
            flattened.update({str(k): str(v) for k, v in entry.items()})
        return flattened
    raise AssertionError("Unexpected decrypted payload format")


@pytest.fixture(name="fixed_encryption_random")
def fixture_fixed_encryption_random(
    monkeypatch: pytest.MonkeyPatch,
    sjcl_fixture: dict[str, Any],
) -> None:
    """Patch SJCL randomness with deterministic salt and IV values."""
    salt = sjcl_fixture["encrypted_data"].get("salt") or sjcl_fixture["keys"]["salt"]
    fixed_salt = base64.b64decode(salt)
    fixed_iv = base64.b64decode(sjcl_fixture["encrypted_data"]["iv"])

    # SJCL encrypt path requests 12 random bytes for IV.
    fixed_iv += b"\x00" * (12 - len(fixed_iv))

    random_values = [fixed_salt, fixed_iv]

    def _fixed_random(size: int) -> bytes:
        value = random_values.pop(0)
        assert len(value) == size
        return value

    monkeypatch.setattr(sjcl_mod, "get_random_bytes", _fixed_random)


@pytest.mark.usefixtures("sjcl_fixture_path")
@pytest.mark.parametrize("sjcl_fixture_name", ["sercomm"])
def test_sercomm_decrypt(
    base_url: URL,
    sjcl_fixture: dict[str, Any],
) -> None:
    """Decrypt SERCOMM fixture and compare with expected clear payload."""
    api = VodafoneStationSercommApi(
        url=base_url,
        username="username",
        password=sjcl_fixture["keys"]["password"],
        session=cast("Any", FakeSession()),
    )

    api.salt = sjcl_fixture["keys"]["salt"]

    plaintext = api._sjcl_decrypt(sjcl_fixture["encrypted_data"])  # noqa: SLF001

    assert _normalize_plain_payload(plaintext) == sjcl_fixture["decrypted_data"]


@pytest.mark.usefixtures("sjcl_fixture_path", "fixed_encryption_random")
@pytest.mark.parametrize("sjcl_fixture_name", ["sercomm"])
def test_sercomm_encrypt(
    base_url: URL,
    sjcl_fixture: dict[str, Any],
) -> None:
    """Encrypt SERCOMM fixture and compare with expected encrypted payload."""
    api = VodafoneStationSercommApi(
        url=base_url,
        username="username",
        password=sjcl_fixture["keys"]["password"],
        session=cast("Any", FakeSession()),
    )

    api.salt = sjcl_fixture["keys"]["salt"]
    data = api._sjcl_build_string(sjcl_fixture["decrypted_data"])  # noqa: SLF001
    encrypted_json_data = api._sjcl_encrypt(data)  # noqa: SLF001

    assert (
        _normalize_encrypted_payload(encrypted_json_data)
        == sjcl_fixture["encrypted_data"]
    )


@pytest.mark.usefixtures("sjcl_fixture_path")
@pytest.mark.parametrize("sjcl_fixture_name", ["ultrahub"])
def test_ultrahub_encrypt(
    base_url: URL,
    sjcl_fixture: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Encrypt ULTRAHUB fixture and compare with expected encrypted payload."""
    api = VodafoneStationUltraHubApi(
        url=base_url,
        username="username",
        password=sjcl_fixture["keys"]["password"],
        session=cast("Any", FakeSession()),
    )

    api.salt = sjcl_fixture["keys"]["salt"]
    api.salt_web_ui = sjcl_fixture["keys"]["salt_web_ui"]

    fixed_iv = base64.b64decode(sjcl_fixture["encrypted_data"]["iv"])
    # SJCL encrypt path requests 16 random bytes for IV.
    fixed_iv += b"\x00" * (16 - len(fixed_iv))
    monkeypatch.setattr(os, "urandom", lambda size: fixed_iv[:size])

    encrypted_json_data = api._encrypt_string()  # noqa: SLF001

    # Compare both content and insertion order.
    assert list(json.loads(encrypted_json_data).items()) == list(
        sjcl_fixture["encrypted_data"].items()
    )


def test_truncate_iv_loop_increments_for_large_output_length() -> None:
    """Exercise truncate_iv branch that increments the IV length loop."""
    truncated = sjcl_mod.truncate_iv(b"0123456789abcdef", 1 << 24, 8)
    assert len(truncated) <= EXPECTED_NONCE_MAX_LEN


def test_get_aes_mode_invalid_raises() -> None:
    """Reject unsupported AES modes with SJCLError."""
    with pytest.raises(SJCLError, match="MODE_NOT-A-MODE"):
        sjcl_mod.get_aes_mode("not-a-mode")


def test_sjcl_decrypt_rejects_invalid_payload_fields() -> None:
    """Cover decrypt validation errors for cipher, adata and version."""
    sjcl = sjcl_mod.SJCL()
    encrypted = _normalize_encrypted_payload(sjcl.encrypt(b"payload", "passphrase"))

    bad_cipher = encrypted.copy()
    bad_cipher["cipher"] = "des"
    with pytest.raises(SJCLError, match="only aes cipher supported"):
        sjcl.decrypt(bad_cipher, "passphrase")

    bad_adata = encrypted.copy()
    bad_adata["adata"] = "not-empty"
    with pytest.raises(SJCLError, match="additional authentication data"):
        sjcl.decrypt(bad_adata, "passphrase")

    bad_version = encrypted.copy()
    bad_version["v"] = 2
    with pytest.raises(SJCLError, match="only version 1"):
        sjcl.decrypt(bad_version, "passphrase")


def test_sjcl_decrypt_rejects_salt_length_and_key_size() -> None:
    """Cover decrypt validation errors for salt size and derived key length."""
    sjcl = sjcl_mod.SJCL()
    encrypted = _normalize_encrypted_payload(sjcl.encrypt(b"payload", "passphrase"))

    bad_salt = encrypted.copy()
    bad_salt["salt"] = base64.b64encode(b"1234567").decode("utf-8")
    with pytest.raises(SJCLError, match="salt should be 8 bytes long"):
        sjcl.decrypt(bad_salt, "passphrase")

    bad_ks = encrypted.copy()
    bad_ks["ks"] = 192
    with pytest.raises(SJCLError, match="key length should be 16 bytes or 32 bytes"):
        sjcl.decrypt(bad_ks, "passphrase")


def test_sjcl_decrypt_ccm_fixes_base64_padding() -> None:
    """Cover CCM decrypt branch that restores missing base64 padding."""
    sjcl = sjcl_mod.SJCL()
    # Use lengths that produce '=' padding in both iv and ct base64 payloads.
    plaintext = b"ab"
    encrypted = _normalize_encrypted_payload(
        sjcl.encrypt(plaintext, "passphrase", mode="ccm", iv_length=13)
    )

    unpadded = encrypted.copy()
    unpadded["salt"] = unpadded["salt"].rstrip("=")
    unpadded["iv"] = unpadded["iv"].rstrip("=")
    unpadded["ct"] = unpadded["ct"].rstrip("=")

    assert sjcl.decrypt(unpadded, "passphrase") == plaintext


def test_sjcl_encrypt_decrypt_roundtrip_gcm() -> None:
    """Cover GCM encrypt/decrypt nonce path branches."""
    sjcl = sjcl_mod.SJCL()
    plaintext = b"gcm-roundtrip"
    encrypted = sjcl.encrypt(plaintext, "passphrase", mode="gcm", iv_length=12)
    assert sjcl.decrypt(encrypted, "passphrase") == plaintext
