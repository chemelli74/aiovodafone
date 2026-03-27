"""Tests for the UltraHub model API implementation."""

from __future__ import annotations

import asyncio
from http import HTTPMethod
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientResponseError

from aiovodafone.exceptions import (
    GenericResponseError,
)
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeCookieJar, FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine

    from yarl import URL

HTTP_OK = 200
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


def _make_login_reply(
    json_data: dict[str, Any], cookies: dict[str, object] | None = None
) -> tuple[dict[str, Any], FakeResponse]:
    return (json_data, FakeResponse(json_data=json_data, cookies=cookies))


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
