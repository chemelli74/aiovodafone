"""Tests for the Technicolor model API implementation."""

from __future__ import annotations

import asyncio
from http import HTTPMethod
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientResponseError

from aiovodafone.const import WIFI_DATA
from aiovodafone.exceptions import AlreadyLogged, CannotAuthenticate, ResultTimeoutError
from aiovodafone.models.technicolor import VodafoneStationTechnicolorApi
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from yarl import URL

HASH_LEN = 32


def _api(base_url: URL) -> VodafoneStationTechnicolorApi:
    return VodafoneStationTechnicolorApi(
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


def test_encrypt_string_returns_32_chars(base_url: URL) -> None:
    """Ensure credential hashing returns expected hash size."""
    api = _api(base_url)
    encrypted = cast(
        "str", asyncio.run(_acall(api, "_encrypt_string", "pass", "salt", "websalt"))
    )
    assert len(encrypted) == HASH_LEN


def test_convert_uptime(base_url: URL) -> None:
    """Ensure uptime conversion returns timezone-aware datetime."""
    api = _api(base_url)
    before = api.convert_uptime("10")
    assert before.tzinfo is not None


def test_get_csrf_token_already_set(base_url: URL) -> None:
    """Ensure CSRF retrieval short-circuits when header is already set."""
    api = _api(base_url)
    api.headers["X-CSRF-Token"] = "token"
    asyncio.run(_acall(api, "_get_csrf_token"))
    assert api.headers["X-CSRF-Token"] == "token"


def test_get_csrf_token_force_update_and_set(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure CSRF retrieval refreshes token when forced."""
    api = _api(base_url)
    api.headers["X-CSRF-Token"] = "old"

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data={"token": "new"})

    monkeypatch.setattr(api, "_request_page_result", _request)
    asyncio.run(_acall(api, "_get_csrf_token", force_update=True))
    assert api.headers["X-CSRF-Token"] == "new"


def test_get_csrf_token_missing_token(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure missing CSRF token in response keeps header unset."""
    api = _api(base_url)
    api.headers.pop("X-CSRF-Token", None)

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data={})

    monkeypatch.setattr(api, "_request_page_result", _request)
    asyncio.run(_acall(api, "_get_csrf_token", force_update=True))
    assert "X-CSRF-Token" not in api.headers


def test_trigger_diagnostic_call_returns_when_ready(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure diagnostics polling returns once result is no longer in progress."""
    api = _api(base_url)
    calls = {"idx": 0}

    async def _csrf(*_args: object, **_kwargs: object) -> None:
        return None

    async def _request(
        method: str, _page: str, _payload: object | None = None
    ) -> object:
        async def _post() -> object:
            return FakeResponse(json_data={})

        async def _get() -> object:
            calls["idx"] += 1
            responses = [
                FakeResponse(json_data={"data": {"ping_result": "InProgress"}}),
                FakeResponse(json_data={"data": {"ping_result": "Done"}}),
            ]
            return responses[min(calls["idx"] - 1, 1)]

        handlers: dict[str, Callable[[], Coroutine[object, object, object]]] = {
            HTTPMethod.POST: _post,
            HTTPMethod.GET: _get,
        }
        return await handlers[method]()

    async def _sleep(_seconds: int) -> None:
        return None

    monkeypatch.setattr(api, "_get_csrf_token", _csrf)
    monkeypatch.setattr(api, "_request_page_result", _request)
    monkeypatch.setattr("aiovodafone.models.technicolor.asyncio.sleep", _sleep)

    result = cast(
        "dict[str, object]",
        asyncio.run(
            _acall(
                api,
                "_trigger_diagnostic_call",
                "ping",
                "ping_res",
                {"a": 1},
                "ping_result",
                retries=3,
            )
        ),
    )
    result_data = cast("dict[str, object]", result["data"])
    assert result_data["ping_result"] == "Done"


def test_trigger_diagnostic_call_timeout(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure diagnostics polling raises timeout after retry budget."""
    api = _api(base_url)

    async def _csrf(*_args: object, **_kwargs: object) -> None:
        return None

    async def _request(
        method: str, _page: str, _payload: object | None = None
    ) -> object:
        async def _post() -> object:
            return FakeResponse(json_data={})

        async def _get() -> object:
            raise ClientResponseError(
                cast("Any", object()), (), status=500, message="err"
            )

        handlers: dict[str, Callable[[], Coroutine[object, object, object]]] = {
            HTTPMethod.POST: _post,
            HTTPMethod.GET: _get,
        }
        return await handlers[method]()

    async def _sleep(_seconds: int) -> None:
        return None

    monkeypatch.setattr(api, "_get_csrf_token", _csrf)
    monkeypatch.setattr(api, "_request_page_result", _request)
    monkeypatch.setattr("aiovodafone.models.technicolor.asyncio.sleep", _sleep)

    with pytest.raises(ResultTimeoutError):
        asyncio.run(
            _acall(
                api,
                "_trigger_diagnostic_call",
                "ping",
                "ping_res",
                {},
                "ping_result",
                retries=2,
            )
        )


def test_login_success(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure login succeeds with valid salt and session responses."""
    api = _api(base_url)
    responses = [
        FakeResponse(json_data={"salt": "s", "saltwebui": "w"}),
        FakeResponse(json_data={}),
        FakeResponse(json_data={}),
    ]

    async def _request(*_args: object, **_kwargs: object) -> object:
        return responses.pop(0)

    monkeypatch.setattr(api, "_request_page_result", _request)
    assert asyncio.run(api.login()) is True


def test_login_force_logout_adds_logout_flag(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure force_logout login includes logout flag in payload."""
    api = _api(base_url)
    responses = [
        FakeResponse(json_data={"salt": "s", "saltwebui": "w"}),
        FakeResponse(json_data={}),
        FakeResponse(json_data={}),
    ]
    payloads: list[dict[str, object]] = []

    async def _request(*_args: object, **_kwargs: object) -> object:
        payload = cast("dict[str, object]", _kwargs.get("payload", {}))
        payloads.append(payload)
        return responses.pop(0)

    monkeypatch.setattr(api, "_request_page_result", _request)
    assert asyncio.run(api.login(force_logout=True)) is True
    assert payloads[1].get("logout") == "true"


def test_login_already_logged(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure already-logged response maps to AlreadyLogged exception."""
    api = _api(base_url)
    responses = [
        FakeResponse(json_data={"salt": "s", "saltwebui": "w"}),
        FakeResponse(json_data={"error": "error", "message": "MSG_LOGIN_150"}),
    ]

    async def _request(*_args: object, **_kwargs: object) -> object:
        return responses.pop(0)

    monkeypatch.setattr(api, "_request_page_result", _request)
    with pytest.raises(AlreadyLogged):
        asyncio.run(api.login())


def test_login_bad_credentials(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure invalid credentials response raises CannotAuthenticate."""
    api = _api(base_url)
    responses = [
        FakeResponse(json_data={"salt": "s", "saltwebui": "w"}),
        FakeResponse(json_data={"error": "error", "message": "other"}),
    ]

    async def _request(*_args: object, **_kwargs: object) -> object:
        return responses.pop(0)

    monkeypatch.setattr(api, "_request_page_result", _request)
    with pytest.raises(CannotAuthenticate):
        asyncio.run(api.login())


def test_get_devices_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure host table is transformed into device map correctly."""
    api = _api(base_url)
    payload = {
        "data": {
            "hostTbl": [
                {
                    "active": "true",
                    "layer1interface": "WiFi 2.4",
                    "ipaddress": "1.1.1.2",
                    "hostname": "phone",
                    "physaddress": "AA",
                    "type": "mobile",
                },
                {
                    "active": "false",
                    "layer1interface": "Ethernet",
                    "ipaddress": "1.1.1.3",
                    "hostname": "pc",
                    "physaddress": "BB",
                    "type": "computer",
                },
            ]
        }
    }

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_request_page_result", _request)
    data = asyncio.run(api.get_devices_data())
    assert data["AA"].connection_type == "WiFi"
    assert data["BB"].connection_type == "Ethernet"


def test_get_sensor_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure status endpoint payload maps to sensor fields."""
    api = _api(base_url)
    payload = {
        "data": {
            "serialnumber": "s",
            "firmwareversion": "f",
            "hardwaretype": "h",
            "uptime": "1",
            "WANStatus": "up",
            "CMStatus": "ok",
            "LanMode": "router",
        }
    }

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_request_page_result", _request)
    data = asyncio.run(api.get_sensor_data())
    assert data["wan_status"] == "up"


def test_get_wifi_data_returns_empty(base_url: URL) -> None:
    """Ensure unimplemented Wi-Fi endpoint returns empty structure."""
    api = _api(base_url)
    assert asyncio.run(api.get_wifi_data()) == {WIFI_DATA: {}}


def test_get_docis_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure DOCSIS payload is normalized into downstream/upstream structure."""
    api = _api(base_url)
    payload = {
        "data": {
            "ofdm_downstream": [
                {
                    "channelid_ofdm": "od",
                    "ChannelType": "OFDM",
                    "start_frequency": "1",
                    "FFT_ofdm": "1024",
                    "power_ofdm": "-1",
                    "locked_ofdm": "true",
                }
            ],
            "downstream": [
                {
                    "channelid": "d",
                    "ChannelType": "QAM",
                    "CentralFrequency": "2",
                    "FFT": "256",
                    "power": "0",
                    "locked": "true",
                }
            ],
            "ofdma_upstream": [
                {
                    "channelidup": "ou",
                    "ChannelType": "OFDMA",
                    "start_frequency": "3",
                    "FFT": "128",
                    "power": "1",
                    "RangingStatus": "ok",
                }
            ],
            "upstream": [
                {
                    "channelidup": "u",
                    "ChannelType": "ATDMA",
                    "CentralFrequency": "4",
                    "FFT": "64",
                    "power": "2",
                    "RangingStatus": "ok",
                }
            ],
            "operational": "up",
        }
    }

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_request_page_result", _request)
    data = asyncio.run(api.get_docis_data())
    assert data["status"] == "up"
    assert "od" in data["downstream"]
    assert "u" in data["upstream"]


def test_get_voice_data_with_and_without_data(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure voice status payload is parsed into line and general data."""
    api = _api(base_url)
    payload = {
        "data": {
            "callnumber1": "123",
            "LineStatus1": "up",
            "status1": "ok",
            "DocsisStatus": "ready",
        }
    }

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(json_data=payload)

    monkeypatch.setattr(api, "_request_page_result", _request)
    data = asyncio.run(api.get_voice_data())
    assert data["line1"]["call_number"] == "123"
    assert data["general"]["status"] == "ready"


def test_restart_router_and_logout(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure restart and logout call expected endpoints."""
    api = _api(base_url)
    calls: list[tuple[str, str]] = []

    async def _request(*_args: object, **_kwargs: object) -> object:
        method = cast("str", _args[0])
        page = cast("str", _args[1])
        calls.append((method, page))
        return FakeResponse(json_data={})

    monkeypatch.setattr(api, "_request_page_result", _request)
    asyncio.run(api.restart_router())
    asyncio.run(api.logout())
    assert (HTTPMethod.POST, "api/v1/sta_restart") in calls
    assert (HTTPMethod.POST, "api/v1/session/logout") in calls


def test_diagnostic_convenience_methods(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure ping, traceroute, and DNS resolve delegate to shared trigger."""
    api = _api(base_url)

    async def _trigger(*_args: object, **_kwargs: object) -> object:
        return {"ok": True, "args": _args}

    monkeypatch.setattr(api, "_trigger_diagnostic_call", _trigger)
    assert asyncio.run(api.ping("1.1.1.1"))["ok"] is True
    assert asyncio.run(api.traceroute("1.1.1.1"))["ok"] is True
    assert asyncio.run(api.dns_resolve("example.com"))["ok"] is True
