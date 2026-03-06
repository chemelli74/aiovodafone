"""Tests for model registry and device detection."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientConnectorError

from aiovodafone.exceptions import ModelNotSupported
from aiovodafone.models import DeviceType, get_device_type, init_device_class
from aiovodafone.models.sercomm import VodafoneStationSercommApi
from aiovodafone.models.technicolor import VodafoneStationTechnicolorApi
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from yarl import URL

MIN_ATTEMPTS = 2


def test_init_device_class_sercomm(base_url: URL) -> None:
    """Ensure Sercomm device type initializes Sercomm API class."""
    session = FakeSession()
    api = init_device_class(
        base_url,
        DeviceType.SERCOMM,
        {"username": "u", "password": "p"},
        cast("Any", session),
    )
    assert isinstance(api, VodafoneStationSercommApi)


def test_init_device_class_technicolor(base_url: URL) -> None:
    """Ensure Technicolor device type initializes Technicolor API class."""
    session = FakeSession()
    api = init_device_class(
        base_url,
        DeviceType.TECHNICOLOR,
        {"username": "u", "password": "p"},
        cast("Any", session),
    )
    assert isinstance(api, VodafoneStationTechnicolorApi)


def test_init_device_class_ultrahub(base_url: URL) -> None:
    """Ensure UltraHub device type initializes UltraHub API class."""
    session = FakeSession()
    api = init_device_class(
        base_url,
        DeviceType.ULTRAHUB,
        {"username": "u", "password": "p"},
        cast("Any", session),
    )
    assert isinstance(api, VodafoneStationUltraHubApi)


def test_init_device_class_unsupported_type_raises(base_url: URL) -> None:
    """Ensure unsupported device types raise ModelNotSupported."""
    session = FakeSession()
    with pytest.raises(ModelNotSupported):
        init_device_class(
            base_url,
            "Unsupported".lower(),  # type: ignore[arg-type]
            {"username": "u", "password": "p"},
            cast("Any", session),
        )


def _session_for_detection(response: FakeResponse) -> FakeSession:
    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        return response

    return FakeSession(get_impl=_get)


def test_get_device_type_detects_technicolor() -> None:
    """Detect Technicolor model from login endpoint response payload."""
    response = FakeResponse(
        status=200,
        text_data='{"data": {"ModelName": "Technicolor"}}',
        json_data={"data": {"ModelName": "Technicolor"}},
    )
    session = _session_for_detection(response)
    device_type, url = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.TECHNICOLOR
    assert str(url).startswith("https://")


def test_get_device_type_detects_ultrahub_and_clears_cookie_jar() -> None:
    """Detect UltraHub model and verify cookie cleanup side effect."""
    response = FakeResponse(
        status=200,
        text_data='{"X_VODAFONE_ServiceStatus_1": "ok"}',
        json_data={"X_VODAFONE_ServiceStatus_1": "ok"},
    )
    session = _session_for_detection(response)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.ULTRAHUB
    assert session.cookie_jar.cleared is True


def test_get_device_type_detects_sercomm_from_html() -> None:
    """Detect Sercomm model from csrf token found in HTML."""
    response = FakeResponse(
        status=200,
        text_data="<script>var csrf_token = 'abc';</script>",
        json_data={},
        content_type="text/html",
    )
    session = _session_for_detection(response)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.SERCOMM


def test_get_device_type_skips_invalid_json_and_raises() -> None:
    """Raise ModelNotSupported when JSON cannot be decoded or matched."""
    response = FakeResponse(
        status=200,
        text_data="{invalid-json",
        json_data={},
        content_type="application/json",
    )
    session = _session_for_detection(response)
    with pytest.raises(ModelNotSupported):
        asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))


def test_get_device_type_continues_after_connection_error_then_succeeds() -> None:
    """Continue protocol probing after connector error and still detect model."""
    calls = {"count": 0}

    def _raise_tls() -> FakeResponse:
        raise ClientConnectorError(cast("Any", object()), OSError("no tls"))

    def _return_html() -> FakeResponse:
        return FakeResponse(
            status=200,
            text_data="<script>var csrf_token = 'abc';</script>",
            json_data={},
            content_type="text/html",
        )

    actions: dict[str, Callable[[], FakeResponse]] = {
        "https": _raise_tls,
        "http": _return_html,
    }

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        url = cast("Any", _args[0])
        calls["count"] += 1
        return actions[url.scheme]()

    session = FakeSession(get_impl=_get)
    device_type, url = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert calls["count"] >= MIN_ATTEMPTS
    assert device_type == DeviceType.SERCOMM
    assert url.scheme == "http"


def test_get_device_type_continues_on_non_200_status() -> None:
    """Continue probing when first endpoint returns non-200 response."""
    calls = {"count": 0}
    responses = iter(
        [
            FakeResponse(status=404, text_data="not found", json_data={}),
            FakeResponse(
                status=200,
                text_data="<script>var csrf_token = 'abc';</script>",
                json_data={},
                content_type="text/html",
            ),
        ]
    )

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        calls["count"] += 1
        return next(responses)

    session = FakeSession(get_impl=_get)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert calls["count"] >= MIN_ATTEMPTS
    assert device_type == DeviceType.SERCOMM
