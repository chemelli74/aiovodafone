# Copyright 2023 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0

"""Vodafone Station models package."""

from collections.abc import Mapping
from enum import StrEnum
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
from .huawei import VodafoneStationHuaweiApi
from .sercomm import VodafoneStationSercommApi
from .technicolor import VodafoneStationTechnicolorApi
from .ultrahub import VodafoneStationUltraHubApi


class DeviceType(StrEnum):
    """Supported device types."""

    HOMEWARE = "Homeware"
    SERCOMM = "Sercomm"
    TECHNICOLOR = "Technicolor"
    ULTRAHUB = "UltraHub"
    HUAWEI = "Huawei"


class_registry: dict[DeviceType, type[VodafoneStationCommonApi]] = {
    DeviceType.HOMEWARE: cast(
        "type[VodafoneStationCommonApi]", VodafoneStationHomewareApi
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
    DeviceType.HUAWEI: cast(
        "type[VodafoneStationCommonApi]", VodafoneStationHuaweiApi
    ),
}


def init_device_class(
    url: URL, device_type: DeviceType, data: Mapping[str, Any], session: ClientSession
) -> VodafoneStationCommonApi:
    """Return inited API class."""
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
    """Find out what kind of device we are talking to.

    The detection is based on the content of the response for a specific url
    available for each device type:
    - Technicolor devices return a JSON response with a ``data`` dictionary
      containing a ``ModelName`` key.
    - UltraHub devices return a JSON response containing a
      ``X_VODAFONE_ServiceStatus_1`` key.
    - Sercomm devices return an HTML response containing a ``csrf_token``
      JavaScript variable.
    - Homeware devices return a JSON response with ``status`` field set to
      ``alive``.
    - Huawei (PT Vodafone ONT) devices return the root login HTML containing
      ``login.cgi`` and ``GetRandCount.asp``.

    Args:
    ----
        host (str): The router's address, e.g. `192.168.1.1`
        session (ClientSession): The client session for HTTP requests

    Returns:
    -------
        device_type: returns the enum entry in DeviceType or raises `ModelNotSupported`
        url: the full router url with scheme and host, e.g. `http://192.168.1.1`

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
                        session.cookie_jar.clear()  # Needed to cleanup the session
                        _LOGGER.debug("Detected device type: %s", DeviceType.ULTRAHUB)
                        return (DeviceType.ULTRAHUB, return_url)
                    if "var csrf_token =" in response_text:
                        _LOGGER.debug("Detected device type: %s", DeviceType.SERCOMM)
                        return (DeviceType.SERCOMM, return_url)
                    if response_json.get("status") == "alive":
                        _LOGGER.debug("Detected device type: %s", DeviceType.HOMEWARE)
                        return (DeviceType.HOMEWARE, return_url)
                    if (
                        "login.cgi" in response_text
                        and "GetRandCount.asp" in response_text
                    ):
                        _LOGGER.debug("Detected device type: %s", DeviceType.HUAWEI)
                        return (DeviceType.HUAWEI, return_url)

            except (
                ClientConnectorSSLError,
                ClientConnectorError,
            ):
                _LOGGER.debug("Unable to login using protocol %s", protocol)
                continue

    raise ModelNotSupported
