# Copyright 2023 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for Huawei (PT Vodafone) model API implementation."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from http import HTTPMethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import pytest

from aiovodafone.const import WIFI_DATA, WifiBand, WifiType
from aiovodafone.exceptions import CannotAuthenticate, GenericLoginError
from aiovodafone.models.huawei import (
    VodafoneStationHuaweiApi,
    _decode_js_string,
    _parse_ctor_calls,
)
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from yarl import URL

FIXTURES = Path(__file__).parent / "fixtures" / "huawei"


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8", errors="replace")


def _api(base_url: URL, session: FakeSession | None = None) -> VodafoneStationHuaweiApi:
    return VodafoneStationHuaweiApi(
        base_url,
        "vodafone",
        "secret",
        cast("Any", session or FakeSession()),
    )


def _acall(
    obj: object, method_name: str, *args: object, **kwargs: object
) -> Coroutine[object, object, object]:
    method = cast(
        "Callable[..., Coroutine[object, object, object]]",
        getattr(obj, method_name),
    )
    return method(*args, **kwargs)


def test_decode_js_string() -> None:
    """Decode Huawei \\xNN escapes."""
    assert _decode_js_string(r"192\x2e168\x2e1\x2e1") == "192.168.1.1"
    assert _decode_js_string("\ufefftoken") == "token"


def test_parse_ctor_calls_user_device() -> None:
    """Parse USERDevice constructors from GetLanUserDevInfo fixture."""
    calls = _parse_ctor_calls(_fixture("GetLanUserDevInfo.asp"), "USERDevice")
    assert len(calls) >= 6
    assert calls[0][2].lower().count(":") == 5


def test_convert_uptime_day_string(base_url: URL) -> None:
    """Parse day(s) HH:MM:SS uptime format."""
    api = _api(base_url)
    before = datetime.now(tz=UTC)
    boot = api.convert_uptime("1 day(s) 05:09:51")
    after = datetime.now(tz=UTC)
    expected_delta = timedelta(days=1, hours=5, minutes=9, seconds=51)
    assert before - expected_delta - timedelta(seconds=2) <= boot <= after - expected_delta + timedelta(
        seconds=2
    )


def test_convert_uptime_seconds(base_url: URL) -> None:
    """Parse integer-second uptime."""
    api = _api(base_url)
    boot = api.convert_uptime("120")
    assert datetime.now(tz=UTC) - boot >= timedelta(seconds=100)


def test_init_device_class_huawei(base_url: URL) -> None:
    """Ensure Huawei device type initializes Huawei API class."""
    from aiovodafone.models import DeviceType, init_device_class

    api = init_device_class(
        base_url,
        DeviceType.HUAWEI,
        {"username": "u", "password": "p"},
        cast("Any", FakeSession()),
    )
    assert isinstance(api, VodafoneStationHuaweiApi)


def test_get_device_type_detects_huawei() -> None:
    """Detect Huawei model from root login HTML markers."""
    from aiovodafone.models import DeviceType, get_device_type

    response = FakeResponse(
        status=200,
        text_data=_fixture("login_page.html"),
        json_data={},
        content_type="text/html",
    )

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        return response

    session = FakeSession(get_impl=_get)
    device_type, url = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.HUAWEI
    assert url.host == "192.168.1.1"


def test_login_success_sets_session_cookie(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Successful login stores the raw Cookie=sid=... header value."""
    api = _api(base_url)
    calls: list[str] = []

    class _Resp:
        def __init__(self, status: int, text: str, headers: dict[str, str]) -> None:
            self.status = status
            self._text = text
            self.headers = headers

        async def text(self) -> str:
            return self._text

        async def read(self) -> bytes:
            return self._text.encode()

        def getall(self, key: str, default: list[str] | None = None) -> list[str]:
            if key.lower() == "set-cookie" and "Set-Cookie" in self.headers:
                return [self.headers["Set-Cookie"]]
            return default or []

    class _Headers(dict[str, str]):
        def getall(self, key: str, default: list[str] | None = None) -> list[str]:
            for k, v in self.items():
                if k.lower() == key.lower():
                    return [v]
            return default or []

    class _Session:
        def __init__(self) -> None:
            self.cookie_jar = type("J", (), {"clear": lambda self: None})()

        async def request(self, method: str, url: object, **_kwargs: object) -> _Resp:
            path = str(url)
            calls.append(path)
            if "GetRandCount" in path:
                return _Resp(200, "abc123token", _Headers())
            if "login.cgi" in path:
                return _Resp(
                    200,
                    "Waiting...",
                    _Headers(
                        {
                            "Set-Cookie": (
                                "Cookie=sid=deadbeef:Language:portuguese:id=1;"
                                "path=/;HttpOnly"
                            )
                        }
                    ),
                )
            # Optional login-page probe for productName.
            return _Resp(
                200,
                "var productName = 'HG8247B7\x2d8N';",
                _Headers(),
            )

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    class _Connector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.TCPConnector",
        _Connector,
    )
    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.ClientSession",
        lambda **_kwargs: _Session(),
    )
    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.DummyCookieJar",
        lambda: object(),
    )

    # Skip onttoken refresh (would need authenticated GETs).
    async def _no_token(self: VodafoneStationHuaweiApi) -> None:
        return None

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_refresh_onttoken", _no_token)

    assert asyncio.run(_acall(api, "login")) is True
    assert api._session_cookie == "Cookie=sid=deadbeef:Language:portuguese:id=1"  # noqa: SLF001
    assert any("GetRandCount" in c for c in calls)
    assert any("login.cgi" in c for c in calls)


def test_login_failure_raises(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing sid cookie raises CannotAuthenticate."""

    class _Resp:
        status = 200
        headers: dict[str, str] = {}

        async def text(self) -> str:
            return "fail"

        async def read(self) -> bytes:
            return b"fail"

        def getall(self, *_args: object, **_kwargs: object) -> list[str]:
            return []

    class _Session:
        async def request(self, *_args: object, **_kwargs: object) -> _Resp:
            return _Resp()

        async def __aenter__(self) -> _Session:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    class _Connector:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def close(self) -> None:
            return None

    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.TCPConnector", _Connector
    )
    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.ClientSession",
        lambda **_kwargs: _Session(),
    )
    monkeypatch.setattr(
        "aiovodafone.models.huawei.aiohttp.DummyCookieJar", lambda: object()
    )

    api = _api(base_url)
    with pytest.raises(CannotAuthenticate):
        asyncio.run(_acall(api, "login"))


def test_get_devices_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Parse LAN devices from fixture."""
    api = _api(base_url)
    api._session_cookie = "Cookie=sid=test"  # noqa: SLF001

    async def _text(self: VodafoneStationHuaweiApi, page: str, **_kwargs: object) -> str:
        assert "GetLanUserDevInfo" in page
        return _fixture("GetLanUserDevInfo.asp")

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_request_text", _text)
    devices = asyncio.run(_acall(api, "get_devices_data"))
    assert isinstance(devices, dict)
    assert len(devices) >= 5
    sample = next(iter(devices.values()))
    assert sample.mac
    assert sample.connection_type in {"WiFi", "Ethernet"}


def test_get_sensor_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Parse sensor fields from index, WAN, and status fixtures."""
    api = _api(base_url)
    api._session_cookie = "Cookie=sid=test"  # noqa: SLF001
    api._product_name = "HG8247B7-8N"  # noqa: SLF001

    async def _text(self: VodafoneStationHuaweiApi, page: str, **_kwargs: object) -> str:
        if page == "index.asp":
            return _fixture("index.asp")
        if "getwanlist" in page:
            return _fixture("getwanlist.asp")
        if "Status_ptvdf" in page:
            return _fixture("Status_ptvdf.asp")
        if "sipphonenum" in page:
            return _fixture("sipphonenumvdf.asp")
        if "wanipv6" in page:
            return _fixture("html_bbsp_common_wanipv6state.asp")
        raise AssertionError(page)

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_request_text", _text)
    data = cast("dict[str, Any]", asyncio.run(_acall(api, "get_sensor_data")))
    assert data["sys_model_name"]
    assert data["sys_firmware_version"]
    # Status page uptime is seconds; index falls back to day(s) HH:MM:SS.
    assert data["sys_uptime"]
    assert data["wan_ip4_addr"] == "203.0.113.10"
    assert data["inter_ip_address"] == "203.0.113.10"
    assert data["fiber_ready"] == "1"
    assert data["sys_serial_number"] == "TESTSERIAL00000001"
    assert data["sys_hardware_version"] == "3F80.A"
    assert data["sys_cpu_usage"] == "24%"
    assert data["sys_memory_usage"] == "12%"
    # Numeric HA sensors must not be present when the router has no value.
    assert "down_str" not in data
    assert "up_str" not in data
    assert data["phone_num1"] == "+15555550100"


def test_get_wifi_data(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Parse Wi-Fi SSIDs and passwords from fixtures."""
    api = _api(base_url)
    api._session_cookie = "Cookie=sid=test"  # noqa: SLF001

    async def _text(self: VodafoneStationHuaweiApi, page: str, **_kwargs: object) -> str:
        if page == "overview.asp":
            return _fixture("overview.asp")
        if "getWlanPsw" in page:
            return _fixture("getWlanPsw.asp")
        raise AssertionError(page)

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_request_text", _text)
    data = cast("dict[str, Any]", asyncio.run(_acall(api, "get_wifi_data")))
    wifi = data[WIFI_DATA]
    assert wifi["main"]["on"] == 1
    assert wifi["main"]["ssid"] == "TestSSID"
    assert wifi["main"]["password"]
    assert wifi["guest"]["on"] == 0
    assert "qr_code" in wifi["guest"]
    assert wifi["main_5g"]["on"] == 1
    assert wifi["guest_5g"]["ssid"].endswith("Guest")


def test_set_wifi_status_posts_enable(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """set_wifi_status posts Enable to the correct WLANConfiguration instance."""
    api = _api(base_url)
    api._session_cookie = "Cookie=sid=test"  # noqa: SLF001
    api.csrf_token = "tok123"
    seen: dict[str, object] = {}

    async def _text(
        self: VodafoneStationHuaweiApi,
        page: str,
        **kwargs: object,
    ) -> str:
        seen["page"] = page
        seen["method"] = kwargs.get("method")
        seen["payload"] = kwargs.get("payload")
        return "ok"

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_request_text", _text)

    async def _refresh(self: VodafoneStationHuaweiApi) -> None:
        self.csrf_token = "tok456"

    monkeypatch.setattr(VodafoneStationHuaweiApi, "_refresh_onttoken", _refresh)

    asyncio.run(
        _acall(
            api,
            "set_wifi_status",
            True,
            WifiType.GUEST,
            WifiBand.BAND_2_4_GHZ,
        )
    )
    assert "WLANConfiguration.2" in str(seen["page"])
    assert seen["method"] == HTTPMethod.POST
    assert "x.Enable=1" in str(seen["payload"])
    assert "x.X_HW_Token=tok123" in str(seen["payload"])


def test_request_text_requires_auth(base_url: URL) -> None:
    """Unauthenticated requests raise GenericLoginError."""
    api = _api(base_url)
    with pytest.raises(GenericLoginError):
        asyncio.run(_acall(api, "_request_text", "index.asp"))
