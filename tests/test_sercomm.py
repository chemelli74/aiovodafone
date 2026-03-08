"""Tests for the Sercomm model API implementation."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import orjson
import pytest
from aiohttp import ClientConnectorError, ClientResponseError

from aiovodafone.const import WIFI_DATA, WifiBand, WifiType
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    GenericResponseError,
)
from aiovodafone.models import sercomm as sercomm_mod
from aiovodafone.models.sercomm import VodafoneStationSercommApi
from aiovodafone.sjcl import build_json_from_sjcl
from tests.conftest import FakeCookieJar, FakeResponse, FakeSession

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Coroutine

    from yarl import URL

HASH_LEN = 64
DERIVED_KEY_LEN = 32

WIFI_CASES_DIR = Path(__file__).parent.joinpath("fixtures", "sercomm")
WIFI_RAW_CASES = cast(
    "list[dict[str, object]]",
    [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(WIFI_CASES_DIR.glob("*.json"))
    ],
)


@pytest.fixture(
    name="wifi_raw_case",
    params=[pytest.param(case, id=cast("str", case["id"])) for case in WIFI_RAW_CASES],
)
def fixture_wifi_raw_case(request: pytest.FixtureRequest) -> dict[str, object]:
    """Provide router Wi-Fi payload cases for format normalization tests."""
    return cast("dict[str, object]", request.param)


def _api(base_url: URL) -> VodafoneStationSercommApi:
    return VodafoneStationSercommApi(
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


def test_list_2_dict(base_url: URL) -> None:
    """Ensure list of key-value objects is flattened into a dict."""
    api = _api(base_url)
    result = asyncio.run(_acall(api, "_list_2_dict", [{"a": 1}, {"b": 2}]))
    assert result == {"a": 1, "b": 2}


def test_get_sercomm_page_dict_and_list(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure Sercomm GET helper handles both dict and list payloads."""
    api = _api(base_url)
    responses = [FakeResponse(json_data={"a": 1}), FakeResponse(json_data=[{"x": 2}])]

    async def _request(*_args: object, **_kwargs: object) -> object:
        return responses.pop(0)

    monkeypatch.setattr(api, "_request_page_result", _request)
    assert asyncio.run(_acall(api, "_get_sercomm_page", "a")) == {"a": 1}
    assert asyncio.run(_acall(api, "_get_sercomm_page", "b")) == {"x": 2}


def test_post_sercomm_page(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure Sercomm POST helper parses JSON response."""
    api = _api(base_url)

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(text_data="raw", json_data={"ok": True})

    monkeypatch.setattr(api, "_request_page_result", _request)
    assert asyncio.run(_acall(api, "_post_sercomm_page", "p", {"a": 1})) == {"ok": True}


def test_check_logged_in(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure logged-in check converts status value to boolean."""
    api = _api(base_url)

    async def _post(*_args: object, **_kwargs: object) -> object:
        return "1"

    monkeypatch.setattr(api, "_post_sercomm_page", _post)
    assert asyncio.run(_acall(api, "_check_logged_in")) is True


def test_get_csrf_token_sets_and_raises(base_url: URL) -> None:
    """Ensure csrf token extraction works and invalid HTML raises error."""
    api = _api(base_url)
    html = "<script>var csrf_token = 'TOKEN';</script>"
    asyncio.run(_acall(api, "_get_csrf_token", html))
    assert api.csrf_token == "TOKEN"

    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_get_csrf_token", "<html></html>"))


def test_get_csrf_token_empty_token_returns_without_setting(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure empty csrf token value leaves object token unchanged."""
    api = _api(base_url)

    def _findall(*_args: object, **_kwargs: object) -> list[str]:
        return ["csrf_token", ""]

    monkeypatch.setattr(sercomm_mod.re, "findall", _findall)
    asyncio.run(_acall(api, "_get_csrf_token", "<script>var x = 1;</script>"))
    assert api.csrf_token == ""


def test_get_user_lang_assigns_encryption_values(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure user_lang call sets encryption key and salt."""
    api = _api(base_url)

    async def _get(*_args: object, **_kwargs: object) -> object:
        return {"encryption_key": "enc", "salt": "0011"}

    monkeypatch.setattr(api, "_get_sercomm_page", _get)
    asyncio.run(_acall(api, "_get_user_lang"))
    assert api.encryption_key == "enc"
    assert api.salt == "0011"


def test_encrypt_helpers(base_url: URL) -> None:
    """Ensure credential and challenge encryption helpers produce hashes."""
    api = _api(base_url)
    api.encryption_key = "k"
    encrypted = cast("str", asyncio.run(_acall(api, "_encrypt_string", "credential")))
    assert len(encrypted) == HASH_LEN
    challenge = cast("str", asyncio.run(_acall(api, "_encrypt_with_challenge", "abc")))
    assert len(challenge) == HASH_LEN


def test_get_challenge(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure challenge field is extracted from login JSON."""
    api = _api(base_url)

    async def _get(*_args: object, **_kwargs: object) -> object:
        return {"challenge": "c"}

    monkeypatch.setattr(api, "_get_sercomm_page", _get)
    assert asyncio.run(_acall(api, "_get_challenge")) == "c"


def test_reset_true_and_false(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure reset helper returns true only for successful status."""
    api = _api(base_url)

    class _FakeClientResponse:
        def __init__(self, status: int) -> None:
            self.status = status

    monkeypatch.setattr(sercomm_mod, "ClientResponse", _FakeClientResponse)

    async def _request_ok(*_args: object, **_kwargs: object) -> object:
        return _FakeClientResponse(200)

    async def _request_other(*_args: object, **_kwargs: object) -> object:
        return object()

    monkeypatch.setattr(api, "_request_page_result", _request_ok)
    assert asyncio.run(_acall(api, "_reset")) is True
    monkeypatch.setattr(api, "_request_page_result", _request_other)
    assert asyncio.run(_acall(api, "_reset")) is False


@pytest.mark.parametrize(
    ("value", "exc"),
    [
        ("2", AlreadyLogged),
        ("3", CannotAuthenticate),
        ("4", CannotAuthenticate),
        ("5", CannotAuthenticate),
        ("7", CannotAuthenticate),
        ("6", GenericLoginError),
    ],
)
def test_login_json_branches(
    base_url: URL, monkeypatch: pytest.MonkeyPatch, value: str, exc: type[Exception]
) -> None:
    """Ensure each login JSON status maps to expected exception path."""
    api = _api(base_url)

    async def _post(*_args: object, **_kwargs: object) -> object:
        return value

    monkeypatch.setattr(api, "_post_sercomm_page", _post)
    with pytest.raises(exc):
        asyncio.run(_acall(api, "_login_json", {}))


def test_login_json_success_and_invalid_response(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure login JSON success is true and invalid payload raises."""
    api = _api(base_url)

    async def _post_ok(*_args: object, **_kwargs: object) -> object:
        return "1"

    async def _post_bad(*_args: object, **_kwargs: object) -> object:
        return "invalid"

    monkeypatch.setattr(api, "_post_sercomm_page", _post_ok)
    assert asyncio.run(_acall(api, "_login_json", {})) is True

    monkeypatch.setattr(api, "_post_sercomm_page", _post_bad)
    with pytest.raises(GenericResponseError):
        asyncio.run(_acall(api, "_login_json", {}))


def test_build_payload_and_wifi_helpers(base_url: URL) -> None:
    """Ensure payload conversion and Wi-Fi helper format logic works."""
    api = _api(base_url)
    payload = build_json_from_sjcl({"x": b"y", "v": 1})
    assert json.loads(payload) == {"x": "y", "v": 1}
    assert (
        asyncio.run(
            _acall(
                api,
                "_wifi_ssid_split_disabled",
                {"split_ssid_enable": "0", "wifi_Frenquency_guest": "both"},
                WifiType.MAIN,
            )
        )
        is True
    )
    assert (
        asyncio.run(
            _acall(
                api,
                "_wifi_ssid_split_disabled",
                {"split_ssid": "1", "wifi_Frenquency_guest": "2Ghz"},
                WifiType.MAIN,
            )
        )
        is False
    )
    assert (
        asyncio.run(
            _acall(
                api,
                "_wifi_ssid_split_disabled",
                {"split_ssid": "1", "wifi_Frenquency_guest": "both"},
                WifiType.GUEST,
            )
        )
        is True
    )
    assert (
        asyncio.run(
            _acall(api, "_get_wifi_format", WifiType.MAIN, WifiBand.BAND_2_4_GHZ)
        )
        == ""
    )
    assert (
        asyncio.run(
            _acall(api, "_get_wifi_format", WifiType.GUEST, WifiBand.BAND_5_GHZ)
        )
        == "_guest_5g"
    )


def test_format_sensor_wifi_data(
    base_url: URL,
    monkeypatch: pytest.MonkeyPatch,
    wifi_raw_case: dict[str, object],
) -> None:
    """Ensure encrypted Wi-Fi data is normalized and guest QR is included."""
    api = _api(base_url)
    raw = cast("list[dict[str, str]]", wifi_raw_case["raw"])
    expected_present = cast("list[str]", wifi_raw_case["expected_present"])
    expected_absent = cast("list[str]", wifi_raw_case["expected_absent"])

    def _decrypt(*_args: object, **_kwargs: object) -> str:
        return orjson.dumps(raw).decode("utf-8")

    async def _qr(*_args: object, **_kwargs: object) -> object:
        return b"qr"

    monkeypatch.setattr(api, "_sjcl_decrypt", _decrypt)
    monkeypatch.setattr(api, "_generate_guest_qr_code", _qr)

    data = cast(
        "dict[str, dict[str, object]]",
        asyncio.run(_acall(api, "_format_sensor_wifi_data", {"ct": "x"})),
    )
    assert WIFI_DATA in data
    for key in expected_present:
        assert key in data[WIFI_DATA]
    for key in expected_absent:
        assert key not in data[WIFI_DATA]


def test_convert_uptime(base_url: URL) -> None:
    """Ensure Sercomm uptime string converts to timezone-aware datetime."""
    api = _api(base_url)
    value = api.convert_uptime("0:1:2")
    assert value.tzinfo == UTC


def test_login_connection_error(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure connector failures are converted to CannotConnect."""
    api = _api(base_url)

    async def _request(*_args: object, **_kwargs: object) -> object:
        raise ClientConnectorError(cast("Any", object()), OSError("down"))

    monkeypatch.setattr(api, "_request_page_result", _request)
    with pytest.raises(CannotConnect):
        asyncio.run(api.login())


def test_login_plain_challenge_flow(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure login uses challenge flow when encryption key is absent."""
    api = _api(base_url)
    first = FakeResponse(
        text_data="<script>var csrf_token = 'TOKEN';</script>", json_data={}
    )

    async def _request(*_args: object, **_kwargs: object) -> object:
        return first

    async def _lang() -> None:
        api.encryption_key = ""
        api.salt = "0011223344556677"

    async def _set() -> None:
        return None

    async def _reset() -> bool:
        return True

    async def _challenge() -> str:
        return "c"

    async def _login_json(payload: dict[str, object]) -> bool:
        return "challenge" in payload

    monkeypatch.setattr(api, "_request_page_result", _request)
    monkeypatch.setattr(api, "_get_user_lang", _lang)
    monkeypatch.setattr(api, "_set_cookie", _set)
    monkeypatch.setattr(api, "_reset", _reset)
    monkeypatch.setattr(api, "_get_challenge", _challenge)
    monkeypatch.setattr(api, "_login_json", _login_json)
    assert asyncio.run(api.login()) is True


def test_login_encrypted_second_try(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure login retries with plain username after auth failure."""
    api = _api(base_url)
    first = FakeResponse(
        text_data="<script>var csrf_token = 'TOKEN';</script>", json_data={}
    )

    async def _raise_auth(_payload: dict[str, object]) -> bool:
        raise CannotAuthenticate

    async def _return_login(payload: dict[str, object]) -> bool:
        return payload["LoginName"] == api.username

    attempts = iter([_raise_auth, _return_login])

    async def _request(*_args: object, **_kwargs: object) -> object:
        return first

    async def _lang() -> None:
        api.encryption_key = "key"
        api.salt = "0011223344556677"

    async def _noop(*_args: object, **_kwargs: object) -> object:
        return None

    async def _login_json(payload: dict[str, object]) -> bool:
        strategy = cast(
            "Callable[[dict[str, object]], Awaitable[bool]]",
            next(attempts),
        )
        return await strategy(payload)

    monkeypatch.setattr(api, "_request_page_result", _request)
    monkeypatch.setattr(api, "_get_user_lang", _lang)
    monkeypatch.setattr(api, "_set_cookie", _noop)
    monkeypatch.setattr(api, "_reset", _noop)
    monkeypatch.setattr(api, "_login_json", _login_json)
    assert asyncio.run(api.login()) is True


def test_get_devices_data_no_devices_and_parse_devices(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure device parser handles empty and populated device responses."""
    api = _api(base_url)
    payloads = [
        {"other": "x"},
        {
            "wifi_user": "on|t|name|AA|1.1.1.2||2.4;",
            "wifi_guest": "on|t|g|BB|1.1.1.3||5;",
            "ethernet": "t|pc|CC|1.1.1.4;bad",
        },
    ]

    async def _get(*_args: object, **_kwargs: object) -> object:
        return payloads.pop(0)

    monkeypatch.setattr(api, "_get_sercomm_page", _get)
    assert asyncio.run(api.get_devices_data()) == {}
    data = asyncio.run(api.get_devices_data())
    assert "AA" in data
    assert data["AA"].connection_type == "Wifi (Main)"
    assert "BB" in data
    assert data["BB"].connection_type == "Wifi (Guest)"
    assert "CC" in data
    assert data["CC"].connection_type == "Ethernet"


def test_get_devices_data_handles_malformed_line(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure malformed device lines are ignored safely."""
    api = _api(base_url)

    async def _get(*_args: object, **_kwargs: object) -> object:
        return {
            "wifi_user": "on|bad;",
            "wifi_guest": "",
            "ethernet": "",
        }

    monkeypatch.setattr(api, "_get_sercomm_page", _get)
    assert asyncio.run(api.get_devices_data()) == {}


def test_sensor_wifi_docis_voice_logout(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure sensor, Wi-Fi, docis, voice, and logout flows behave."""
    api = _api(base_url)
    overview_attr = "_overview"
    setattr(api, overview_attr, {"x": 1})
    payloads = [{"a": 1}, {"b": 2}, {"c": 3}]

    async def _get(*_args: object, **_kwargs: object) -> object:
        return payloads.pop(0)

    async def _format(*_args: object, **_kwargs: object) -> object:
        return {WIFI_DATA: {"k": {"on": 1}}}

    monkeypatch.setattr(api, "_get_sercomm_page", _get)
    data = asyncio.run(api.get_sensor_data())
    assert data["x"] == 1

    async def _get_wifi(*_args: object, **_kwargs: object) -> object:
        return {"encrypted": "x"}

    monkeypatch.setattr(api, "_get_sercomm_page", _get_wifi)
    monkeypatch.setattr(api, "_format_sensor_wifi_data", _format)
    wifi = asyncio.run(api.get_wifi_data())
    assert WIFI_DATA in wifi
    assert asyncio.run(api.get_docis_data()) == {}
    assert asyncio.run(api.get_voice_data()) == {}
    asyncio.run(api.logout())
    cookie_jar = cast("FakeCookieJar", api.session.cookie_jar)
    assert cookie_jar.cleared is True


def test_restart_connection_and_router(
    base_url: URL, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ensure restart behaviors handle login, header errors, and timeout."""
    api = _api(base_url)
    calls = {"login": 0, "post": 0}

    async def _check() -> bool:
        return False

    async def _login() -> bool:
        calls["login"] += 1
        return True

    async def _post(*_args: object, **_kwargs: object) -> object:
        calls["post"] += 1
        return {}

    monkeypatch.setattr(api, "_check_logged_in", _check)
    monkeypatch.setattr(api, "login", _login)
    monkeypatch.setattr(api, "_post_sercomm_page", _post)
    asyncio.run(api.restart_connection("wan"))
    assert calls["login"] == 1
    assert calls["post"] == 1

    async def _post_header_err(*_args: object, **_kwargs: object) -> object:
        raise ClientResponseError(
            cast("Any", object()), (), status=400, message="Invalid header token"
        )

    monkeypatch.setattr(api, "_post_sercomm_page", _post_header_err)
    asyncio.run(api.restart_connection("wan"))

    async def _post_other_err(*_args: object, **_kwargs: object) -> object:
        raise ClientResponseError(
            cast("Any", object()), (), status=400, message="other"
        )

    monkeypatch.setattr(api, "_post_sercomm_page", _post_other_err)
    with pytest.raises(ClientResponseError):
        asyncio.run(api.restart_connection("wan"))

    async def _request_timeout(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError

    monkeypatch.setattr(api, "_request_page_result", _request_timeout)
    asyncio.run(api.restart_router())


def test_set_wifi_status(base_url: URL, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure Wi-Fi status update sends payload and validates reply."""
    api = _api(base_url)
    wifi_plain_data_attr = "_wifi_plain_data"
    setattr(
        api,
        wifi_plain_data_attr,
        {
            "split_ssid_enable": "0",
            "wifi_ssid": "main",
            "wifi_ssid_5g": "other",
            "wifi_network_onoff": "1",
            "wifi_network_onoff_5g": "1",
            "wifi_password": "p a",
        },
    )

    async def _request(*_args: object, **_kwargs: object) -> object:
        return FakeResponse(
            text_data="<script>var csrf_token = 'TOKEN';</script>", json_data={}
        )

    async def _post(*_args: object, **_kwargs: object) -> object:
        return "1"

    monkeypatch.setattr(api, "_request_page_result", _request)
    monkeypatch.setattr(api, "_post_sercomm_page", _post)
    asyncio.run(api.set_wifi_status(False, WifiType.MAIN, WifiBand.BAND_2_4_GHZ))

    async def _post_bad(*_args: object, **_kwargs: object) -> object:
        return "0"

    monkeypatch.setattr(api, "_post_sercomm_page", _post_bad)
    with pytest.raises(GenericResponseError):
        asyncio.run(api.set_wifi_status(True, WifiType.MAIN, WifiBand.BAND_2_4_GHZ))
