"""Tests for common API base helpers."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from http import HTTPMethod
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientResponseError

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.exceptions import GenericResponseError
from tests.conftest import FakeCookieJar, FakeResponse, FakeSession

if TYPE_CHECKING:
    from yarl import URL


class DummyCommonApi(VodafoneStationCommonApi):
    """Concrete test double for exercising common API base helpers."""

    def convert_uptime(self, _uptime: str) -> datetime:
        """Return a timezone-aware datetime for abstract method compliance."""
        return datetime.now(tz=UTC)

    async def login(self, _force_logout: bool = False) -> bool:
        """Return a successful login result for test scaffolding."""
        return True

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Return an empty device map for abstract method compliance."""
        return {}

    async def get_sensor_data(self) -> dict[str, object]:
        """Return empty sensor data for abstract method compliance."""
        return {}

    async def get_docis_data(self) -> dict[str, object]:
        """Return empty DOCSIS data for abstract method compliance."""
        return {}

    async def get_voice_data(self) -> dict[str, object]:
        """Return empty voice data for abstract method compliance."""
        return {}

    async def restart_connection(self, _connection_type: str) -> None:
        """No-op restart connection implementation for tests."""
        return

    async def restart_router(self) -> None:
        """No-op restart router implementation for tests."""
        return

    async def logout(self) -> None:
        """No-op logout implementation for tests."""
        return

    async def get_wifi_data(self) -> dict[str, object]:
        """Return empty Wi-Fi data for abstract method compliance."""
        return {}

    async def set_wifi_status(
        self, _enable: bool, _wifi_type: object, _band: object
    ) -> None:
        """No-op Wi-Fi status setter for abstract method compliance."""
        return


HTTP_OK = 200


async def _acall(
    obj: object, method_name: str, *args: object, **kwargs: object
) -> object:
    method = cast("Any", getattr(obj, method_name))
    return await method(*args, **kwargs)


def test_set_cookie_updates_cookie_jar(base_url: URL) -> None:
    """Verify cookie setup updates session cookie jar."""
    api = DummyCommonApi(base_url, "u", "p", cast("Any", FakeSession()))
    asyncio.run(_acall(api, "_set_cookie"))
    cookie_jar = cast("FakeCookieJar", api.session.cookie_jar)
    assert cookie_jar.updated


def test_request_page_result_ok(base_url: URL) -> None:
    """Verify request helper returns response for HTTP 200."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse(status=200)

    api = DummyCommonApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    response = cast(
        "FakeResponse",
        asyncio.run(_acall(api, "_request_page_result", HTTPMethod.GET, "status")),
    )
    assert response.status == HTTP_OK


def test_request_page_result_non_200_raises(base_url: URL) -> None:
    """Verify request helper raises on non-success status."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        return FakeResponse(status=500)

    api = DummyCommonApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_request_page_result", HTTPMethod.GET, "status"))


def test_request_page_result_client_response_error_raises(base_url: URL) -> None:
    """Verify request helper wraps aiohttp response errors."""

    async def _request(*_args: object, **_kwargs: object) -> FakeResponse:
        raise ClientResponseError(cast("Any", object()), (), status=400, message="boom")

    api = DummyCommonApi(
        base_url, "u", "p", cast("Any", FakeSession(request_impl=_request))
    )
    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_request_page_result", HTTPMethod.GET, "status"))


def test_generate_guest_qr_code_returns_png_stream(base_url: URL) -> None:
    """Verify guest QR generation returns a PNG byte stream."""
    api = DummyCommonApi(base_url, "u", "p", cast("Any", FakeSession()))
    stream = cast(
        "Any",
        asyncio.run(_acall(api, "_generate_guest_qr_code", "ssid", "pass", "WPA")),
    )
    signature = stream.read(8)
    assert signature == b"\x89PNG\r\n\x1a\n"
