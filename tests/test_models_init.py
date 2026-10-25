# Copyright 2023 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for model registry and device detection."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

import pytest
from aiohttp import ClientConnectorError

from aiovodafone.const import DEFAULT_TIMEOUT
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

NOT_FOUND = FakeResponse(status=404, text_data="not found", json_data={})
SERCOMM_HTML = FakeResponse(
    status=200,
    text_data="<script>var csrf_token = 'abc';</script>",
    json_data={},
    content_type="text/html",
)
HOMEWARE_ALIVE = FakeResponse(
    status=200,
    text_data='{"status": "alive"}',
    json_data={"status": "alive"},
)
HOMEWARE_PARAMS = {"getSessionStatus": "true"}

type Probe = tuple[URL, dict[str, object]]
type Responder = Callable[[URL, dict[str, object]], FakeResponse | BaseException]


def _refused() -> ClientConnectorError:
    return ClientConnectorError(cast("Any", object()), OSError("refused"))


def _session_for_detection(
    respond: FakeResponse | BaseException | Responder,
    probed: list[Probe] | None = None,
) -> FakeSession:
    """Create a session whose probe requests are answered by ``respond``.

    ``respond`` is a fixed response, an exception to raise, or a callable that
    receives the probed URL and the request keyword arguments and returns one
    of the two. Every probe is appended to ``probed`` as ``(url, kwargs)``.
    """

    def _get(url: URL, *_args: object, **kwargs: object) -> FakeResponse:
        if probed is not None:
            probed.append((url, kwargs))
        result = respond(url, kwargs) if callable(respond) else respond
        if isinstance(result, BaseException):
            raise result
        return result

    return FakeSession(get_impl=_get)


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
        (SERCOMM_HTML, DeviceType.SERCOMM),
        (HOMEWARE_ALIVE, DeviceType.HOMEWARE),
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
    probed: list[Probe] = []
    session = _session_for_detection(
        lambda _url, kwargs: (
            HOMEWARE_ALIVE if kwargs.get("params") == HOMEWARE_PARAMS else NOT_FOUND
        ),
        probed,
    )
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.HOMEWARE
    homeware_probes = [kw for _, kw in probed if kw.get("params") == HOMEWARE_PARAMS]
    assert len(homeware_probes) == 1


def test_get_device_type_ultrahub_iterates_internal_fields_entries() -> None:
    """UltraHub detection tries each X_INTERNAL_FIELDS entry until one matches."""

    def _respond(_url: URL, kwargs: dict[str, object]) -> FakeResponse:
        params = cast("dict[str, str]", kwargs.get("params") or {})
        # Newer firmware only echoes back the language field
        if params.get("X_INTERNAL_FIELDS") == "X_VODAFONE_WebUI_Language":
            return FakeResponse(
                status=200,
                text_data='{"X_VODAFONE_WebUI_Language": "en"}',
                json_data={"X_VODAFONE_WebUI_Language": "en"},
            )
        return FakeResponse(status=200, text_data="{}", json_data={})

    probed: list[Probe] = []
    session = _session_for_detection(_respond, probed)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert device_type == DeviceType.ULTRAHUB
    assert session.cookie_jar.cleared is True
    probed_fields = [
        cast("dict[str, str]", kw.get("params") or {}).get("X_INTERNAL_FIELDS")
        for _, kw in probed
    ]
    assert probed_fields.index("X_VODAFONE_ServiceStatus_1") < probed_fields.index(
        "X_VODAFONE_WebUI_Language"
    )


def test_get_device_type_continues_after_connection_error_then_succeeds() -> None:
    """Continue protocol probing after connector error and still detect model."""
    probed: list[Probe] = []
    session = _session_for_detection(
        lambda url, _kwargs: _refused() if url.scheme == "https" else SERCOMM_HTML,
        probed,
    )
    device_type, url = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert len(probed) >= MIN_ATTEMPTS
    assert device_type == DeviceType.SERCOMM
    assert url.scheme == "http"


def test_get_device_type_continues_on_non_200_status() -> None:
    """Continue probing when first endpoint returns non-200 response."""
    responses = iter([NOT_FOUND, SERCOMM_HTML])
    probed: list[Probe] = []
    session = _session_for_detection(lambda _url, _kwargs: next(responses), probed)
    device_type, _ = asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert len(probed) >= MIN_ATTEMPTS
    assert device_type == DeviceType.SERCOMM


def test_get_device_type_raises_cannot_connect_on_timeout() -> None:
    """Raise CannotConnect when every probe times out."""
    session = _session_for_detection(TimeoutError())
    with pytest.raises(CannotConnect):
        asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))


def test_get_device_type_continues_after_https_timeout_then_detects() -> None:
    """A router silently dropping HTTPS must not abort detection.

    Regression test for Technicolor CGA6444VF: HTTPS probes time out, the
    Technicolor ``api/v1/login_conf`` endpoint answers over HTTP.
    """

    def _respond(url: URL, _kwargs: dict[str, object]) -> FakeResponse | BaseException:
        if url.scheme == "https":
            return TimeoutError()
        if url.path == "/api/v1/login_conf":
            return FakeResponse(
                status=200,
                text_data='{"error":"ok","data":{"ModelName":"CGA6444VF"}}',
                json_data={"error": "ok", "data": {"ModelName": "CGA6444VF"}},
                content_type="application/json",
            )
        return NOT_FOUND

    probed: list[Probe] = []
    session = _session_for_detection(_respond, probed)
    device_type, url = asyncio.run(get_device_type("192.168.0.1", cast("Any", session)))
    assert device_type == DeviceType.TECHNICOLOR
    assert url.scheme == "http"
    https_probes = [u for u, _ in probed if u.scheme == "https"]
    assert [u.path for u in https_probes] == ["/login.lp"]


def test_get_device_type_timeout_with_other_response_raises_not_supported() -> None:
    """Reachable but unknown device reports ModelNotSupported, not CannotConnect."""
    session = _session_for_detection(
        lambda url, _kwargs: TimeoutError() if url.scheme == "https" else NOT_FOUND
    )
    with pytest.raises(ModelNotSupported):
        asyncio.run(get_device_type("192.168.0.1", cast("Any", session)))


def test_get_device_type_https_timeout_http_refused_raises_cannot_connect() -> None:
    """HTTPS timing out and HTTP refusing every connection means unreachable."""
    probed: list[Probe] = []
    session = _session_for_detection(
        lambda url, _kwargs: TimeoutError() if url.scheme == "https" else _refused(),
        probed,
    )
    with pytest.raises(CannotConnect):
        asyncio.run(get_device_type("192.168.0.1", cast("Any", session)))
    # Each protocol is probed only once, then skipped for the other device types
    assert [u.scheme for u, _ in probed] == ["https", "http"]


def test_get_device_type_passes_probe_timeout() -> None:
    """Probe requests use DEFAULT_TIMEOUT instead of the session default."""
    probed: list[Probe] = []
    session = _session_for_detection(HOMEWARE_ALIVE, probed)
    asyncio.run(get_device_type("192.168.1.1", cast("Any", session)))
    assert probed
    assert all(kw.get("timeout") is DEFAULT_TIMEOUT for _, kw in probed)
