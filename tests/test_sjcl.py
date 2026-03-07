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
from aiovodafone.models.sercomm import VodafoneStationSercommApi
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeSession

if TYPE_CHECKING:
    from yarl import URL


SJCL_FIXTURES_DIR = Path(__file__).parent.joinpath("fixtures", "sjcl")
SJCL_FIXTURE_NAMES = tuple(
    sorted(path.stem for path in SJCL_FIXTURES_DIR.glob("*.json"))
)


@pytest.fixture(name="sjcl_fixture_name", params=SJCL_FIXTURE_NAMES)
def fixture_sjcl_fixture_name(request: pytest.FixtureRequest) -> str:
    """Return fixture name for a router SJCL payload."""
    return cast("str", request.param)


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


def _normalize_plain_payload(plaintext: str | bytes) -> dict[str, str]:
    """Normalize decrypted JSON payload to a flat string dictionary."""
    raw_text = plaintext.decode("utf-8") if isinstance(plaintext, bytes) else plaintext

    try:
        decoded = json.loads(raw_text)
    except json.JSONDecodeError:
        # UltraHub fixture payload is URL-encoded key/value data.
        return dict(urllib.parse.parse_qsl(raw_text, keep_blank_values=True))

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
