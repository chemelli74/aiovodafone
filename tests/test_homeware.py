"""Tests for the Homeware model API implementation."""

from __future__ import annotations

import asyncio
import hashlib as _hashlib
import secrets as _secrets
from http import HTTPStatus
from typing import TYPE_CHECKING, Any, cast

import pytest

import aiovodafone.models.homeware as _homeware_module
from aiovodafone.const import WIFI_DATA, WifiBand, WifiType
from aiovodafone.exceptions import GenericLoginError
from aiovodafone.models.homeware import TechnicolorSRP, VodafoneStationHomewareApi
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from yarl import URL

_SHA256_HEX_LEN = 64


def _api(base_url: URL) -> VodafoneStationHomewareApi:
    return VodafoneStationHomewareApi(
        base_url, "user", "pass", cast("Any", FakeSession())
    )


# ---------------------------------------------------------------------------
# TechnicolorSRP - client_public_key_hex
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("token_seed", "expected_hex"),
    [
        (4, "10"),  # d_public = pow(2, 4, K) = 16 -> "10", even length, no padding
        (0, "01"),  # d_public = pow(2, 0, K) = 1  -> "1",  odd length, padded
    ],
)
def test_srp_client_public_key_hex(
    token_seed: int,
    expected_hex: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """client_public_key_hex zero-pads odd-length hex and returns even-length."""
    fixed_token = token_seed.to_bytes(32, "big")
    monkeypatch.setattr(_secrets, "token_bytes", lambda _: fixed_token)
    srp = TechnicolorSRP("u", "p")
    assert srp.client_public_key_hex == expected_hex


# ---------------------------------------------------------------------------
# TechnicolorSRP - calculate_proofs
# ---------------------------------------------------------------------------


def test_srp_calculate_proofs_invalid_server_key_raises() -> None:
    """Raise GenericLoginError when server public key is zero mod K."""
    srp = TechnicolorSRP("u", "p")
    with pytest.raises(GenericLoginError, match="B % K == 0"):
        srp.calculate_proofs("aabb", "00")  # int("00", 16) = 0, 0 % K = 0


def test_srp_calculate_proofs_h_zero_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raise GenericLoginError when scrambling parameter h is zero (mocked SHA-256)."""

    class _ZeroDigest:
        def digest(self) -> bytes:
            return b"\x00" * 32

    monkeypatch.setattr(_hashlib, "sha256", lambda _data: _ZeroDigest())
    srp = TechnicolorSRP("u", "p")
    with pytest.raises(GenericLoginError, match="h == 0"):
        srp.calculate_proofs("aabb", "03")


def test_srp_calculate_proofs_full_round_trip() -> None:
    """Successful calculation returns a 64-char hex proof; second call is cached."""
    srp = TechnicolorSRP("u", "p")
    proof = srp.calculate_proofs("deadbeef" * 8, "03")
    assert isinstance(proof, str)
    assert len(proof) == _SHA256_HEX_LEN
    # Second call returns the cached value (covers the early-return branch)
    assert srp.calculate_proofs("deadbeef" * 8, "03") == proof


def test_srp_calculate_proofs_odd_g_hex_padded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Odd-length g_hex is zero-padded before hashing.

    token_bytes seed=9 deterministically produces g_hex of length 511 (odd)
    for username="u", password="p", salt="aa", server_public="03".
    """
    fixed_token = (9).to_bytes(32, "big")
    monkeypatch.setattr(_secrets, "token_bytes", lambda _: fixed_token)
    srp = TechnicolorSRP("u", "p")
    proof = srp.calculate_proofs("aa", "03")
    assert isinstance(proof, str)
    assert len(proof) == _SHA256_HEX_LEN


# ---------------------------------------------------------------------------
# TechnicolorSRP - verify_server
# ---------------------------------------------------------------------------


def test_srp_verify_server_before_calculate_raises() -> None:
    """Raise RuntimeError when verify_server is called before calculate_proofs."""
    srp = TechnicolorSRP("u", "p")
    with pytest.raises(RuntimeError, match="calculate_proofs first"):
        srp.verify_server("anyproof")


def test_srp_verify_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """verify_server delegates to hmac.compare_digest; returns True or False."""
    results = iter([True, False])
    monkeypatch.setattr(
        _homeware_module.hmac, "compare_digest", lambda _a, _b: next(results)
    )
    srp = TechnicolorSRP("u", "p")
    srp.calculate_proofs("deadbeef" * 8, "03")  # populates _server_verification
    assert srp.verify_server("any") is True  # first compare -> True
    assert srp.verify_server("any") is False  # second compare -> False


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


def test_login_force_logout_warns_and_succeeds(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """force_logout logs a warning but login still completes successfully."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf1"),
            FakeResponse(json_data={"s": "aa", "B": "03"}),
            FakeResponse(json_data={"M": "proof"}, cookies={}),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    monkeypatch.setattr(TechnicolorSRP, "verify_server", lambda *_: True)
    assert asyncio.run(api.login(force_logout=True)) is True


def test_login_missing_salt_raises(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raise GenericLoginError when first auth response has no salt."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf1"),
            FakeResponse(json_data={}),  # no "s" key
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    with pytest.raises(GenericLoginError):
        asyncio.run(api.login())


def test_login_missing_server_proof_raises(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raise GenericLoginError when second auth response has no server proof."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf1"),
            FakeResponse(json_data={"s": "aa", "B": "03"}),
            FakeResponse(json_data={}, cookies={}),  # no "M" key
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    with pytest.raises(GenericLoginError):
        asyncio.run(api.login())


def test_login_server_proof_mismatch_raises(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raise GenericLoginError when server proof verification fails."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf1"),
            FakeResponse(json_data={"s": "aa", "B": "03"}),
            FakeResponse(json_data={"M": "wrongproof"}, cookies={}),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    monkeypatch.setattr(TechnicolorSRP, "verify_server", lambda *_: False)
    with pytest.raises(GenericLoginError):
        asyncio.run(api.login())


def test_login_success(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful login returns True."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf1"),
            FakeResponse(json_data={"s": "deadbeef", "B": "03"}),
            FakeResponse(json_data={"M": "serverproof"}, cookies={"session": "abc"}),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    monkeypatch.setattr(TechnicolorSRP, "verify_server", lambda *_: True)
    assert asyncio.run(api.login()) is True


# ---------------------------------------------------------------------------
# get_devices_data  (also covers _parse_device and _collect_devices branches)
# ---------------------------------------------------------------------------


def test_get_devices_data_json_path(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """JSON path covers all _parse_device and _collect_devices branches.

    Parsing branches covered:
    - Device with no MAC                              -> filtered out
    - Primary fields (State=1, wireless, IPv4, ...)   -> connected WiFi device
    - Fallback fields (State=0, ethernet, DhcpLeaseIP, ...) -> disconnected device
    - X_VF_ADTI.Class fallback + unknown InterfaceType -> type/connection_type=""

    Collection branches covered:
    - Flat lists: ethList, wifiList24, wifiList5, guestWifi24, guestWifi5
    - wifiList nested: non-dict bridge entry skipped, non-dict band entry skipped,
      dict band with devices collected
    """
    api = _api(base_url)
    payload: dict[str, Any] = {
        "ethList": [
            {
                "MACAddress": "AA:BB:CC:DD:EE:01",
                "State": "1",
                "InterfaceType": "wireless",
                "IPv4": "192.168.1.2",
                "HostName": "dev1",
                "X_VODAFONE_Fingerprint.Class": "phone",
                "Radio": "2.4GHz",
            },
            {"InterfaceType": "ethernet"},  # no MAC -> filtered out
        ],
        "wifiList24": [
            {
                "MACAddress": "AA:BB:CC:DD:EE:02",
                "State": "0",
                "InterfaceType": "ethernet",
                "DhcpLeaseIP": "10.0.0.1",
                "FriendlyName": "printer",
                "Class": "printer",
                "radio": "5GHz",
            }
        ],
        "wifiList5": [
            {
                "MACAddress": "AA:BB:CC:DD:EE:03",
                "InterfaceType": "other",  # unknown -> ""
                "X_VF_ADTI.Class": "tablet",
            }
        ],
        "guestWifi24": [{"MACAddress": "AA:BB:CC:DD:EE:04"}],
        "guestWifi5": [{"MACAddress": "AA:BB:CC:DD:EE:05"}],
        "wifiList": {
            "wifiActiveCount": 3,  # non-dict bridge entry -> skipped
            "bridge0": {
                "wifiActiveCount": 2,  # non-dict band entry -> skipped
                "band0": {"devices": [{"MACAddress": "AA:BB:CC:DD:EE:06"}]},
            },
        },
    }

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(json_data=payload, content_type="application/json")

    monkeypatch.setattr(api, "_request_page_result", _fake)
    devices = asyncio.run(api.get_devices_data())

    dev1 = devices["AA:BB:CC:DD:EE:01"]
    assert dev1.connected is True
    assert dev1.connection_type == "WiFi"
    assert dev1.ip_address == "192.168.1.2"
    assert dev1.name == "dev1"
    assert dev1.type == "phone"
    assert dev1.wifi == "2.4GHz"

    dev2 = devices["AA:BB:CC:DD:EE:02"]
    assert dev2.connected is False
    assert dev2.connection_type == "Ethernet"
    assert dev2.ip_address == "10.0.0.1"
    assert dev2.name == "printer"
    assert dev2.type == "printer"
    assert dev2.wifi == "5GHz"

    dev3 = devices["AA:BB:CC:DD:EE:03"]
    assert dev3.connection_type == ""
    assert dev3.type == "tablet"

    for mac in ["AA:BB:CC:DD:EE:04", "AA:BB:CC:DD:EE:05", "AA:BB:CC:DD:EE:06"]:
        assert mac in devices


def test_get_devices_data_non_json_path(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Older firmware: devices fetched from separate WiFi and ethernet calls."""
    api = _api(base_url)
    wifi_payload = {"wifiList24": [{"MACAddress": "AA:BB:CC:DD:EE:02"}]}
    eth_payload = {"ethList": [{"MACAddress": "AA:BB:CC:DD:EE:03"}]}
    responses = iter(
        [
            FakeResponse(json_data={}, content_type="text/html"),
            FakeResponse(json_data=wifi_payload),
            FakeResponse(json_data=eth_payload),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    devices = asyncio.run(api.get_devices_data())
    assert "AA:BB:CC:DD:EE:02" in devices
    assert "AA:BB:CC:DD:EE:03" in devices


# ---------------------------------------------------------------------------
# get_sensor_data
# ---------------------------------------------------------------------------


def test_get_sensor_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sensor data is correctly mapped from system info and interface replies."""
    api = _api(base_url)
    sysinfo_payload = {
        "systemParams": {
            "sys_gw_serial": "SN123",
            "sys_gw_version": "v22",
            "sys_hw_version": "hw1",
            "sys_uptime": "1 day",
        }
    }
    interfaces_payload = {"ethstatus": "Up", "dslstatus": "Down"}
    responses = iter(
        [
            FakeResponse(json_data=sysinfo_payload),
            FakeResponse(json_data=interfaces_payload),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    data = asyncio.run(api.get_sensor_data())
    assert data["sys_serial_number"] == "SN123"
    assert data["sys_firmware_version"] == "v22"
    assert data["wan_status"] == "up"
    assert data["cm_status"] == "down"
    assert data["lan_mode"] == ""


# ---------------------------------------------------------------------------
# get_wifi_data
# ---------------------------------------------------------------------------


def test_get_wifi_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Present bands appear in the result; absent bands are omitted."""
    api = _api(base_url)
    status_content = {
        "wifi_status": "On",
        "wifi_ssid": "MainNet",
        "wifi5_status": "Off",
        "wifi5_ssid": "MainNet5",
        # 6 GHz and guest bands absent → skipped (covers the if-False branch)
    }

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(json_data={"status_content": status_content})

    monkeypatch.setattr(api, "_request_page_result", _fake)
    result = asyncio.run(api.get_wifi_data())
    assert result[WIFI_DATA]["main"]["on"] == 1
    assert result[WIFI_DATA]["main"]["ssid"] == "MainNet"
    assert result[WIFI_DATA]["main-5ghz"]["on"] == 0
    assert "main-6ghz" not in result[WIFI_DATA]


# ---------------------------------------------------------------------------
# get_docis_data / get_voice_data
# ---------------------------------------------------------------------------


def test_get_docis_data(base_url: URL) -> None:
    """get_docis_data returns an empty dict."""
    assert asyncio.run(_api(base_url).get_docis_data()) == {}


def test_get_voice_data(base_url: URL) -> None:
    """get_voice_data returns an empty dict."""
    assert asyncio.run(_api(base_url).get_voice_data()) == {}


# ---------------------------------------------------------------------------
# restart_connection / restart_router / logout
# ---------------------------------------------------------------------------


def test_restart_connection_invalid_type(base_url: URL) -> None:
    """Raise ValueError for an unrecognised connection type."""
    with pytest.raises(ValueError, match="Unknown connection type"):
        asyncio.run(_api(base_url).restart_connection("fiber"))


@pytest.mark.parametrize("conn_type", ["dsl", "ethwan"])
def test_restart_connection_valid(
    conn_type: str, base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Restart a valid connection type without raising."""
    api = _api(base_url)

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(text_data="csrf")

    monkeypatch.setattr(api, "_request_page_result", _fake)
    asyncio.run(api.restart_connection(conn_type))  # must not raise


def test_restart_router(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """restart_router completes without error."""
    api = _api(base_url)

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(text_data="csrf")

    monkeypatch.setattr(api, "_request_page_result", _fake)
    asyncio.run(api.restart_router())


def test_logout(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Logout completes without error."""
    api = _api(base_url)

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(text_data="csrf")

    monkeypatch.setattr(api, "_request_page_result", _fake)
    asyncio.run(api.logout())


def test_logout_redirect_to_login_succeeds(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Logout succeeds when the router redirects to the login page."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(text_data="csrf"),
            FakeResponse(status=HTTPStatus.FOUND, text_data="login.lp"),
        ]
    )

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        response = next(responses)
        if response.status == HTTPStatus.FOUND:
            assert _kw["additional_params"] == {"allow_redirects": True}
        return response

    monkeypatch.setattr(api, "_request_page_result", _fake)
    asyncio.run(api.logout())


# ---------------------------------------------------------------------------
# convert_uptime
# ---------------------------------------------------------------------------


def test_convert_uptime_all_components(base_url: URL) -> None:
    """Parse a full uptime string containing all time components."""
    result = _api(base_url).convert_uptime("24 days, 15 hours, 1 minute and 41 seconds")
    assert result.tzinfo is not None
    assert result.microsecond == 0


def test_convert_uptime_partial(base_url: URL) -> None:
    """Parse an uptime string that contains only minutes and seconds."""
    result = _api(base_url).convert_uptime("5 minutes and 41 seconds")
    assert result.tzinfo is not None


def test_convert_uptime_explicit_zero(base_url: URL) -> None:
    """An uptime of zero seconds is valid (literal '0' present in string)."""
    result = _api(base_url).convert_uptime("0 seconds")
    assert result.tzinfo is not None


def test_convert_uptime_invalid_raises(base_url: URL) -> None:
    """Raise ValueError for strings with no recognisable time components."""
    with pytest.raises(ValueError, match="Failed to parse"):
        _api(base_url).convert_uptime("running fine")


# ---------------------------------------------------------------------------
# set_wifi_status  (also covers _get_wifi_settings branches)
# ---------------------------------------------------------------------------


def test_set_wifi_status_bad_settings_raises(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Raise GenericLoginError when wifi-settings page lacks expected JSON block."""
    api = _api(base_url)

    async def _fake(*_a: object, **_kw: object) -> FakeResponse:
        return FakeResponse(text_data="<html>no content</html>")

    monkeypatch.setattr(api, "_request_page_result", _fake)
    with pytest.raises(GenericLoginError):
        asyncio.run(api.set_wifi_status(True, WifiType.MAIN, WifiBand.BAND_2_4_GHZ))


@pytest.mark.parametrize(
    ("wifi_type", "expected_key"),
    [
        (WifiType.MAIN, "multiAP_wifi_enable"),
        (WifiType.GUEST, "wifi_state2"),
    ],
)
def test_set_wifi_status(
    wifi_type: WifiType,
    expected_key: str,
    base_url: URL,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """set_wifi_status selects the correct payload key for each WiFi type."""
    api = _api(base_url)
    responses = iter(
        [
            FakeResponse(
                text_data='var content = {"existing": "val"};'
            ),  # _get_wifi_settings
            FakeResponse(text_data="csrf_tok"),  # _get_csrf_token
            FakeResponse(),  # POST
        ]
    )
    recorded: list[dict[str, Any]] = []

    async def _fake(*_args: object, **_kwargs: object) -> FakeResponse:
        recorded.append(dict(_kwargs))
        return next(responses)

    monkeypatch.setattr(api, "_request_page_result", _fake)
    asyncio.run(api.set_wifi_status(True, wifi_type, WifiBand.BAND_2_4_GHZ))

    payload = recorded[2].get("payload")
    assert payload is not None
    assert expected_key in payload
    assert payload[expected_key] == "1"
    assert payload["action"] == "SAVE"
    assert payload["CSRFtoken"] == "csrf_tok"
