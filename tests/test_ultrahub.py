"""Tests for the UltraHub model API implementation."""

from __future__ import annotations

import asyncio
from http import HTTPMethod
from typing import TYPE_CHECKING, Any, cast

import orjson
import pytest
from aiohttp import ClientResponseError

from aiovodafone.const import WIFI_DATA
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    GenericLoginError,
    GenericResponseError,
)
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeCookieJar, FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from yarl import URL

HTTP_OK = 200
EXPECTED_NONCE_MAX_LEN = 13
DEFAULT_DEVICE_ID = 7


def _api(base_url: URL) -> VodafoneStationUltraHubApi:
    return VodafoneStationUltraHubApi(
        base_url, "user", "pass", cast("Any", FakeSession())
    )


def _acall(
    obj: object, method_name: str, *args: object, **kwargs: object
) -> Coroutine[object, object, object]:
    method = cast(
        "Callable[..., Coroutine[object, object, object]]",
        getattr(obj, method_name),
    )
    return method(*args, **kwargs)


def _scall(obj: object, method_name: str, *args: object, **kwargs: object) -> object:
    method = cast("Callable[..., object]", getattr(obj, method_name))
    return method(*args, **kwargs)


def test_encrypt_string_and_truncate_iv(base_url: URL) -> None:
    """Ensure encryption payload is SJCL-like and IV truncation works."""
    api = _api(base_url)
    value = cast(
        "str", asyncio.run(_acall(api, "_encrypt_string", "abcdefgh", "1234567890"))
    )
    parsed = orjson.loads(value)
    assert parsed["cipher"] == "aes"
    nonce = cast("str", _scall(api, "_truncate_iv", b"0123456789abcdef", 128, 8))
    assert len(nonce) <= EXPECTED_NONCE_MAX_LEN


def test_truncate_iv_loop_increments(base_url: URL) -> None:
    """Ensure nonce truncation loop handles large output lengths."""
    api = _api(base_url)
    nonce = cast("str", _scall(api, "_truncate_iv", b"0123456789abcdef", 1 << 24, 8))
    assert len(nonce) <= EXPECTED_NONCE_MAX_LEN


def test_auto_hub_request_ok_and_csrf(base_url: URL) -> None:
    """Ensure successful request updates csrf token from response JSON."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse(status=200, json_data={"csrf_token": "t"})

    api = VodafoneStationUltraHubApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    response = cast(
        "FakeResponse",
        asyncio.run(_acall(api, "_auto_hub_request_page_result", HTTPMethod.GET, "x")),
    )
    assert response.status == HTTP_OK
    assert api.csrf_token == "t"


def test_auto_hub_request_non_200_raises(base_url: URL) -> None:
    """Ensure non-200 responses are converted to GenericResponseError."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse(status=500, json_data={})

    api = VodafoneStationUltraHubApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_auto_hub_request_page_result", HTTPMethod.GET, "x"))


def test_auto_hub_request_client_error_raises(base_url: URL) -> None:
    """Ensure aiohttp client errors are wrapped as GenericResponseError."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        raise ClientResponseError(cast("Any", object()), (), status=400, message="boom")

    api = VodafoneStationUltraHubApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_auto_hub_request_page_result", HTTPMethod.GET, "x"))


def test_cleanup_session(base_url: URL) -> None:
    """Ensure cleanup resets csrf token and clears cookie jar."""
    api = _api(base_url)
    api.csrf_token = "x"
    asyncio.run(_acall(api, "_cleanup_session"))
    assert api.csrf_token == ""
    cookie_jar = cast("FakeCookieJar", api.session.cookie_jar)
    assert cookie_jar.cleared is True


def test_convert_uptime(base_url: URL) -> None:
    """Ensure uptime conversion returns timezone-aware datetime."""
    api = _api(base_url)
    value = api.convert_uptime("4")
    assert value.tzinfo is not None


def test_login_raises_when_missing_csrf(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure login fails when csrf token is not established."""
    api = _api(base_url)

    async def _auto(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data={})

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    with pytest.raises(CannotAuthenticate):
        asyncio.run(api.login())


def test_login_invalid_password(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure invalid password status raises CannotAuthenticate."""
    api = _api(base_url)
    api.csrf_token = "token"
    replies = [
        FakeResponse(
            json_data={"csrf_token": "t", "X_INTERNAL_ID": 7}, cookies={"a": "b"}
        ),
        FakeResponse(json_data={"X_VODAFONE_WebUISecret": "test-secret"}),
        FakeResponse(json_data={"X_INTERNAL_Password_Status": "Invalid_PWD"}),
    ]

    async def _auto(*_args: object, **_kwargs: object) -> object:
        return replies.pop(0)

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    with pytest.raises(CannotAuthenticate):
        asyncio.run(api.login(force_logout=True))


def test_login_already_logged(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure duplicate-session status raises AlreadyLogged."""
    api = _api(base_url)
    api.csrf_token = "token"
    replies = [
        FakeResponse(
            json_data={"csrf_token": "t", "X_INTERNAL_ID": 7}, cookies={"a": "b"}
        ),
        FakeResponse(json_data={"X_VODAFONE_WebUISecret": "test_secret"}),
        FakeResponse(json_data={"X_INTERNAL_Is_Duplicate": "true"}),
    ]

    async def _auto(*_args: object, **_kwargs: object) -> object:
        return replies.pop(0)

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    with pytest.raises(AlreadyLogged):
        asyncio.run(api.login(force_logout=True))


def test_login_success_and_missing_secret(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure login succeeds with secret and fails when secret is missing."""
    api = _api(base_url)
    api.csrf_token = "token"
    ok_replies = [
        FakeResponse(
            json_data={"csrf_token": "t", "X_INTERNAL_ID": 7}, cookies={"a": "b"}
        ),
        FakeResponse(json_data={"X_VODAFONE_WebUISecret": "test_secret"}),
        FakeResponse(json_data={}),
    ]

    async def _auto_ok(*_args: object, **_kwargs: object) -> object:
        return ok_replies.pop(0)

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto_ok)
    assert asyncio.run(api.login(force_logout=True)) is True
    assert api.id == DEFAULT_DEVICE_ID

    api2 = _api(base_url)
    api2.csrf_token = "token"
    missing_secret = [
        FakeResponse(
            json_data={"csrf_token": "t", "X_INTERNAL_ID": 7}, cookies={"a": "b"}
        ),
        FakeResponse(json_data={}),
    ]

    async def _auto_bad(*_args: object, **_kwargs: object) -> object:
        return missing_secret.pop(0)

    monkeypatch.setattr(api2, "_auto_hub_request_page_result", _auto_bad)
    with pytest.raises(GenericLoginError):
        asyncio.run(api2.login(force_logout=True))


def test_get_devices_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure host entries are transformed into device map."""
    api = _api(base_url)
    payload = {
        "hosts": [
            {
                "Active": "true",
                "Layer1Interface": "WiFi 5",
                "IPv4Address_1_IPAddress": "1.1.1.2",
                "HostName": "phone",
                "PhysAddress": "AA",
                "X_VODAFONE_Fingerprint_Class": "mobile",
                "X_CISCO_COM_RSSI": "-30",
            }
        ]
    }

    async def _auto(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    data = asyncio.run(api.get_devices_data())
    assert data["AA"].connection_type == "WiFi"


def test_get_sensor_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure device details endpoint maps to expected sensor fields."""
    api = _api(base_url)
    payload = {
        "SoftwareVersion": "f",
        "HardwareVersion": "h",
        "SerialNumber": "s",
        "UpTime": "1",
        "X_VODAFONE_WANType": "x",
        "INTERNAL_CPEInterface_List": [
            {"DisplayName": "WWAN", "Phy_Status": "up"},
            {"DisplayName": "WANoE", "Phy_Status": "ok"},
        ],
    }

    async def _auto(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    data = asyncio.run(api.get_sensor_data())
    assert data["wan_status"] == "up"
    assert data["cm_status"] == "ok"


def test_simple_methods(base_url: URL) -> None:
    """Ensure simple and unsupported API methods return expected defaults/errors."""
    api = _api(base_url)
    assert asyncio.run(api.get_wifi_data()) == {WIFI_DATA: {}}
    assert asyncio.run(api.get_docis_data()) == {}
    assert asyncio.run(api.get_voice_data()) == {}


def test_restart_router_suppresses_error_and_cleans(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure restart suppresses response errors and still cleans session."""
    api = _api(base_url)
    api.csrf_token = "t"

    async def _auto(*_args: object, **_kwargs: object) -> object:
        raise GenericResponseError

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    asyncio.run(api.restart_router())
    assert api.csrf_token == ""


def test_logout_behaviour(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure logout handles empty and failing session states safely."""
    api = _api(base_url)
    asyncio.run(api.logout())
    cookie_jar = cast("FakeCookieJar", api.session.cookie_jar)
    assert cookie_jar.cleared is False

    api.csrf_token = "token"

    async def _auto(*_args: object, **_kwargs: object) -> object:
        raise GenericResponseError

    monkeypatch.setattr(api, "_auto_hub_request_page_result", _auto)
    asyncio.run(api.logout())
    assert api.csrf_token == ""
