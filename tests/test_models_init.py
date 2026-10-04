# Copyright 2023 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for model registry and device detection."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientConnectorError

from aiovodafone.exceptions import CannotConnect, ModelNotSupported
from aiovodafone.models import DeviceType, get_device_type, init_device_class
from aiovodafone.models.homeware import VodafoneStationHomewareApi
from aiovodafone.models.sercomm import VodafoneStationSercommApi
from aiovodafone.models.technicolor import VodafoneStationTechnicolorApi
from aiovodafone.models.ultrahub import VodafoneStationUltraHubApi
from tests.conftest import FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Callable

    from yarl import URL

    from aiovodafone.api import VodafoneStationCommonApi

MIN_ATTEMPTS = 2


@pytest.mark.parametrize(
    ("device_type", "expected_class"),
    [
        (DeviceType.SERCOMM, VodafoneStationSercommApi),
        (DeviceType.TECHNICOLOR, VodafoneStationTechnicolorApi),
        (DeviceType.ULTRAHUB, VodafoneStationUltraHubApi),
        (DeviceType.HOMEWARE, VodafoneStationHomewareApi),
    ],
)
def test_init_device_class(
    base_url: URL,
    device_type: DeviceType,
    expected_class: type[VodafoneStationCommonApi],
) -> None:
    """Ensure each device type initializes its matching API class."""
    session = FakeSession()
    api = init_device_class(
        base_url,
        device_type,
        {"username": "u", "password": "p"},
        cast("Any", session),
    )
    assert isinstance(api, expected_class)


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


@pytest.mark.parametrize(
    "marker",
    [
        # Firmware < 01.08.82
        "X_VODAFONE_ServiceStatus_1",
        # Firmware >= 01.08.82 dropped the field above
        "X_VODAFONE_WebUI_Language",
    ],
)
def test_get_device_type_detects_ultrahub_and_clears_cookie_jar(marker: str) -> None:
    """Detect UltraHub model on old and new firmware markers and verify cleanup."""
    response = FakeResponse(
        status=200,
        text_data=f'{{"{marker}": "ok"}}',
        json_data={marker: "ok"},
    )
    session = _session_for_detection(response)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.ULTRAHUB
    assert session.cookie_jar.cleared is True


@pytest.mark.parametrize(
    ("response", "expected_type"),
    [
        (
            FakeResponse(
                status=200,
                text_data="<script>var csrf_token = 'abc';</script>",
                json_data={},
                content_type="text/html",
            ),
            DeviceType.SERCOMM,
        ),
        (
            FakeResponse(
                status=200,
                text_data='{"status": "alive"}',
                json_data={"status": "alive"},
            ),
            DeviceType.HOMEWARE,
        ),
    ],
)
def test_get_device_type_detects(
    response: FakeResponse, expected_type: DeviceType
) -> None:
    """Detect model type from a single distinguishing response payload."""
    session = _session_for_detection(response)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == expected_type


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(
            FakeResponse(
                status=200,
                text_data="{invalid-json",
                json_data={},
                content_type="application/json",
            ),
            id="invalid_json",
        ),
        pytest.param(
            FakeResponse(
                status=200,
                text_data='{"X_OTHER_FIELD": "value"}',
                json_data={"X_OTHER_FIELD": "value"},
            ),
            id="no_internal_fields_marker",
        ),
    ],
)
def test_get_device_type_unmatched_response_raises(response: FakeResponse) -> None:
    """Raise ModelNotSupported when no response matches a known device."""
    session = _session_for_detection(response)
    with pytest.raises(ModelNotSupported):
        asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))


def test_get_device_type_homeware_uses_single_params_entry() -> None:
    """A device with a single params entry is probed once with those params."""
    homeware_params: list[object] = []

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        params = _kwargs.get("params")
        if params == {"getSessionStatus": "true"}:
            homeware_params.append(params)
            return FakeResponse(
                status=200,
                text_data='{"status": "alive"}',
                json_data={"status": "alive"},
            )
        return FakeResponse(status=404, text_data="", json_data={})

    session = FakeSession(get_impl=_get)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.HOMEWARE
    assert homeware_params == [{"getSessionStatus": "true"}]


def test_get_device_type_ultrahub_iterates_internal_fields_entries() -> None:
    """UltraHub detection tries each X_INTERNAL_FIELDS entry until one matches."""
    probed_fields: list[str] = []

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        params = cast("dict[str, str]", _kwargs.get("params") or {})
        internal_fields = params.get("X_INTERNAL_FIELDS")
        if internal_fields:
            probed_fields.append(internal_fields)
        # Newer firmware only echoes back the language field
        if internal_fields == "X_VODAFONE_WebUI_Language":
            return FakeResponse(
                status=200,
                text_data='{"X_VODAFONE_WebUI_Language": "en"}',
                json_data={"X_VODAFONE_WebUI_Language": "en"},
            )
        return FakeResponse(status=200, text_data="{}", json_data={})

    session = FakeSession(get_impl=_get)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.ULTRAHUB
    assert session.cookie_jar.cleared is True
    assert probed_fields.index("X_VODAFONE_ServiceStatus_1") < probed_fields.index(
        "X_VODAFONE_WebUI_Language"
    )


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


def test_get_device_type_raises_cannot_connect_on_timeout() -> None:
    """Convert a TimeoutError while probing into CannotConnect."""

    def _get(*_args: object, **_kwargs: object) -> FakeResponse:
        raise TimeoutError

    session = FakeSession(get_impl=_get)
    with pytest.raises(CannotConnect):
        asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
