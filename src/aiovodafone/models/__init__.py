"""Vodafone Station models package."""

from collections.abc import Mapping
from enum import Enum
from http import HTTPStatus
from typing import Any, cast

import orjson
from aiohttp import (
    ClientConnectorError,
    ClientConnectorSSLError,
    ClientSession,
)
from yarl import URL

from aiovodafone.api import VodafoneStationCommonApi
from aiovodafone.const import _LOGGER, DEVICES_SETTINGS, HEADERS
from aiovodafone.exceptions import ModelNotSupported

from .homeware import VodafoneStationHomewareApi
from .sercomm import VodafoneStationSercommApi
from .technicolor import VodafoneStationTechnicolorApi
from .ultrahub import VodafoneStationUltraHubApi


class DeviceType(str, Enum):
    """Supported device types."""

    HOMEWARE = "Homeware"
    SERCOMM = "Sercomm"
    TECHNICOLOR = "Technicolor"
    ULTRAHUB = "UltraHub"


class_registry: dict[DeviceType, type[VodafoneStationCommonApi]] = {
    DeviceType.HOMEWARE: cast(
        "type[VodafoneStationHomewareApi]", VodafoneStationHomewareApi
    ),
    DeviceType.SERCOMM: cast(
        "type[VodafoneStationCommonApi]", VodafoneStationSercommApi
    ),
    DeviceType.TECHNICOLOR: cast(
        "type[VodafoneStationCommonApi]", VodafoneStationTechnicolorApi
    ),
    DeviceType.ULTRAHUB: cast(
        "type[VodafoneStationCommonApi]", VodafoneStationUltraHubApi
    ),
}


def init_device_class(
    url: URL, device_type: DeviceType, data: Mapping[str, Any], session: ClientSession
) -> VodafoneStationCommonApi:
    """Return the inited API class."""
    if device_type not in class_registry:
        raise ModelNotSupported(f"Device type '{device_type}' not supported")
    api_class: type[VodafoneStationCommonApi] = class_registry[device_type]

    return api_class(
        url,
        data["username"],
        data["password"],
        session,
    )


async def get_device_type(
    host: str,
    session: ClientSession,
) -> tuple[DeviceType, URL]:
    """Find out the device type of a Vodafone Stations and returns it as enum.

    The Technicolor devices always answer with a valid HTTP response, the
    Sercomm returns 404 on a missing page. This helps to determine which we are
    talking with.
    For detecting the Sercomm devices, a look up for a CSRF token is used.

    Args:
    ----
        host (str): The router's address, e.g. `192.168.1.1`
        session (ClientSession): the client session for HTTP requests

    Returns:
    -------
    [
        device_type:
            returns an enum entry in DeviceType or raises `ModelNotSupported`
        url:
            full router url with scheme and host, e.g. `http://192.168.1.1`
    ]

    """
    for device_info in DEVICES_SETTINGS.values():
        api_path = device_info.get("login_url")
        for protocol in ["https", "http"]:
            try:
                return_url = URL(f"{protocol}://{host}")
                url = return_url.joinpath(api_path)
                _LOGGER.debug("Trying url %s", url)
                async with session.get(
                    url,
                    headers=HEADERS,
                    allow_redirects=False,
                    params=device_info.get("params"),
                    ssl=False,
                ) as response:
                    _LOGGER.debug("Response for url %s: %s", url, response.status)
                    if response.status != HTTPStatus.OK:
                        continue

                    response_text = await response.text()
                    response_json: dict[str, Any] = {}
                    if response.content_type == "application/json":
                        try:
                            response_json = orjson.loads(response_text)
                        except orjson.JSONDecodeError:
                            _LOGGER.debug("Failed to decode JSON response from %s", url)

                    if "data" in response_json and "ModelName" in response_json["data"]:
                        _LOGGER.debug(
                            "Detected device type: %s", DeviceType.TECHNICOLOR
                        )
                        return (DeviceType.TECHNICOLOR, return_url)

                    if "X_VODAFONE_ServiceStatus_1" in response_json:
                        session.cookie_jar.clear()  # Needed to cleanup session
                        _LOGGER.debug("Detected device type: %s", DeviceType.ULTRAHUB)
                        return (DeviceType.ULTRAHUB, return_url)

                    if "var csrf_token = " in response_text:
                        _LOGGER.debug("Detected device type: %s", DeviceType.SERCOMM)
                        return (DeviceType.SERCOMM, return_url)

                    if response_json.get("status") == "alive":
                        _LOGGER.debug("Detected device type: %s", DeviceType.HOMEWARE)
                        return (DeviceType.HOMEWARE, return_url)

            except (
                ClientConnectorSSLError,
                ClientConnectorError,
            ):
                _LOGGER.debug("Unable to login using protocol %s", protocol)
                continue

    raise ModelNotSupported
