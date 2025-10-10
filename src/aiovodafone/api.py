"""Support for Vodafone Station."""

import asyncio
import base64
import contextlib
import hashlib
import hmac
import os
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPMethod, HTTPStatus
from http.cookies import SimpleCookie
from typing import Any, cast

import orjson
from aiohttp import (
    ClientConnectorError,
    ClientConnectorSSLError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from yarl import URL

from .const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    DEVICE_SERCOMM_LOGIN_STATUS,
    DEVICE_SERCOMM_LOGIN_URL,
    DEVICE_SERCOMM_TOTAL_FIELDS_NUM,
    DEVICE_TECHNICOLOR_LOGIN_URL,
    DEVICE_TECHNICOLOR_USER_ALREADY_LOGGED_IN,
    DEVICE_ULTRAHUB_LOGIN_URL,
    HEADERS,
    POST_RESTART_TIMEOUT,
)
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    GenericResponseError,
    ModelNotSupported,
    ResultTimeoutError,
)


@dataclass
class VodafoneStationDevice:
    """Vodafone Station device class."""

    connected: bool
    connection_type: str
    ip_address: str
    name: str
    mac: str
    type: str
    wifi: str


class VodafoneStationCommonApi(ABC):
    """Common API calls for Vodafone Station routers."""

    @staticmethod
    async def get_device_type(
        host: str,
        session: ClientSession,
    ) -> tuple[str, URL]:
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
                returns `Sercomm`, `Technicolor` or raises `ModelNotSupported`
            url:
               full router url with scheme and host, e.g. `http://192.168.1.1`
        ]

        """
        urls = [
            DEVICE_TECHNICOLOR_LOGIN_URL,
            DEVICE_SERCOMM_LOGIN_URL,
            DEVICE_ULTRAHUB_LOGIN_URL,
        ]

        for api_path in urls:
            for protocol in ["https", "http"]:
                try:
                    return_url = URL(f"{protocol}://{host}")
                    url = return_url.joinpath(api_path)
                    _LOGGER.debug("Trying url %s", url)
                    async with session.get(
                        url,
                        headers=HEADERS,
                        allow_redirects=False,
                        params={
                            "X_INTERNAL_FIELDS": "X_RDK_ONT_Veip_1_OperationalState"
                        },  # Needed by ULTRAHUN
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
                                _LOGGER.debug(
                                    "Failed to decode JSON response from %s", url
                                )

                        if (
                            "data" in response_json
                            and "ModelName" in response_json["data"]
                        ):
                            _LOGGER.debug("Detected device type: Technicolor")
                            return "Technicolor", return_url

                        if "X_VODAFONE_ServiceStatus_1" in response_json:
                            return "Ultrahub", return_url

                        if "var csrf_token = " in response_text:
                            _LOGGER.debug("Detected device type: Sercomm")
                            return "Sercomm", return_url

                except (
                    ClientConnectorSSLError,
                    ClientConnectorError,
                ):
                    _LOGGER.debug("Unable to login using protocol %s", protocol)
                    continue

        raise ModelNotSupported

    def __init__(
        self,
        url: URL,
        username: str,
        password: str,
        session: ClientSession,
    ) -> None:
        """Initialize the scanner."""
        self.username = username
        self.password = password
        self.base_url = url
        self.headers = HEADERS
        self.session = session
        self.csrf_token: str = ""
        self.encryption_key: str = ""
        self._unique_id: str | None = None
        self._overview: dict[str, Any] = {}
        self._devices: dict[str, VodafoneStationDevice] = {}

    async def _set_cookie(self) -> None:
        """Enable required session cookie."""
        self.session.cookie_jar.update_cookies(
            SimpleCookie(f"domain={self.base_url.host}; name=login_uid; value=1;"),
        )

    async def _request_page_result(
        self,
        method: str,
        page: str,
        payload: dict[str, Any] | None = None,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> ClientResponse:
        """Request data from a web page."""
        _LOGGER.debug("%s page %s from host %s", method, page, self.base_url.host)
        timestamp = int(datetime.now(tz=UTC).timestamp())
        url = self.base_url.joinpath(page).with_query(
            _=timestamp, csrf_token=self.csrf_token
        )
        try:
            response = await self.session.request(
                method,
                url,
                data=payload,
                headers=self.headers,
                timeout=timeout,
                ssl=False,
                allow_redirects=True,
            )
            if response.status != HTTPStatus.OK:
                _LOGGER.warning(
                    "%s page %s from host %s failed: %s",
                    method,
                    page,
                    self.base_url.host,
                    response.status,
                )
                raise GenericResponseError
        except ClientResponseError as err:
            _LOGGER.exception(
                "%s page %s from host %s failed", method, page, self.base_url.host
            )
            raise GenericResponseError from err
        else:
            return response

    @abstractmethod
    def convert_uptime(self, uptime: str) -> datetime:
        """Convert uptime to datetime."""

    @abstractmethod
    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""

    @abstractmethod
    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get router device data."""

    @abstractmethod
    async def get_sensor_data(self) -> dict[str, Any]:
        """Get router sensor data."""

    @abstractmethod
    async def get_docis_data(self) -> dict[str, Any]:
        """Get router docis data."""

    @abstractmethod
    async def get_voice_data(self) -> dict[str, Any]:
        """Get router voice data."""

    @abstractmethod
    async def restart_connection(self, connection_type: str) -> None:
        """Internet Connection restart."""

    @abstractmethod
    async def restart_router(self) -> None:
        """Router restart."""

    @abstractmethod
    async def logout(self) -> None:
        """Router logout."""


class VodafoneStationTechnicolorApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Technicolor firmware."""

    async def _encrypt_string(
        self,
        credential: str,
        salt: str,
        salt_web_ui: str,
    ) -> str:
        """Calculate login hash (password), the salt and the salt (web UI).

        Args:
        ----
            credential (str): login password for the user
            salt (str): salt given by the login response
            salt_web_ui (str): salt given by the web UI

        Returns:
        -------
            str: the hash for the session API

        """
        _LOGGER.debug("Calculate credential hash")
        a = hashlib.pbkdf2_hmac(
            "sha256",
            bytes(credential, "utf-8"),
            bytes(salt, "utf-8"),
            1000,
        ).hex()[:32]
        return hashlib.pbkdf2_hmac(
            "sha256",
            bytes(a, "utf-8"),
            bytes(salt_web_ui, "utf-8"),
            1000,
        ).hex()[:32]

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert uptime to datetime."""
        return datetime.now(tz=UTC) - timedelta(
            seconds=int(uptime),
        )

    async def _get_csrf_token(self, force_update: bool = False) -> None:
        """Retrieve CSRF token."""
        if force_update:
            self.headers.pop("X-CSRF-Token", None)

        if "X-CSRF-Token" in self.headers:
            _LOGGER.debug("CSRF Token already set")
            return

        # Any existing URL will do the job here
        csrf_res = await self._request_page_result(
            HTTPMethod.GET, "api/v1/wifi/1/SSIDEnable"
        )
        csrf_json = await csrf_res.json()
        _LOGGER.debug("csrf call response: %s", csrf_json)

        if token := csrf_json.get("token"):
            _LOGGER.debug("CSRF Token: %s", token)
            self.headers["X-CSRF-Token"] = token
        else:
            _LOGGER.warning("Failed to retrieve CSRF token")

    async def _trigger_diagnostic_call(
        self,
        check_url: str,
        data_url: str,
        payload: dict[str, Any],
        key: str,
        retries: int = 15,
    ) -> dict:
        """Trigger a specific diagnostic request to the router."""
        await self._get_csrf_token(force_update=True)

        url = f"api/v1/sta_diagnostic_utility/{check_url}"
        await self._request_page_result(
            HTTPMethod.POST,
            url,
            payload,
        )

        url = f"api/v1/sta_diagnostic_utility/{data_url}"
        for attempt in range(retries):
            try:
                response = await self._request_page_result(HTTPMethod.GET, url)
                result: dict[str, Any] = await response.json()
                if result and result.get("data", {}).get(key) != "InProgress":
                    return result

                _LOGGER.debug(
                    "'%s' results not ready, retrying (%d/%d)...",
                    key,
                    attempt + 1,
                    retries,
                )
                # sleep for 2 seconds, just like the dashboard does
                await asyncio.sleep(2)
            except ClientResponseError:
                _LOGGER.exception("Failed to retrieve '%s' results", key)

        raise ResultTimeoutError(
            "'%s' results not available after %d retries",
            key,
            retries,
        )

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s (force: %s)", self.base_url.host, force_logout)

        _LOGGER.debug("Get salt for login")
        payload = {"username": self.username, "password": "seeksalthash"}
        salt_response = await self._request_page_result(
            HTTPMethod.POST,
            page="api/v1/session/login",
            payload=payload,
        )

        salt_json = await salt_response.json()

        salt = salt_json["salt"]
        salt_web_ui = salt_json["saltwebui"]

        # Calculate credential hash
        password_hash = await self._encrypt_string(self.password, salt, salt_web_ui)

        # Perform login
        _LOGGER.debug("Perform login")
        payload = {
            "username": self.username,
            "password": password_hash,
        }
        # disconnect other users if force is set
        if force_logout:
            payload["logout"] = "true"
        login_response = await self._request_page_result(
            HTTPMethod.POST,
            page="api/v1/session/login",
            payload=payload,
        )
        login_json = await login_response.json()
        if "error" in login_json and login_json["error"] == "error":
            if login_json["message"] == DEVICE_TECHNICOLOR_USER_ALREADY_LOGGED_IN:
                raise AlreadyLogged
            _LOGGER.error(login_json)
            raise CannotAuthenticate

        # Request menu otherwise the next call fails
        _LOGGER.debug("Get menu")
        await self._request_page_result(HTTPMethod.GET, "api/v1/session/menu")

        return True

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get all connected devices as a map of MAC address and device object.

        Returns
        -------
            dict[str, VodafoneStationDevice]: MAC address maps to VodafoneStationDevice

        """
        _LOGGER.debug("Get hosts")
        host_response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/host/hostTbl"
        )
        host_json = await host_response.json()
        _LOGGER.debug("GET reply (%s)", host_json)

        devices_dict = {}
        for device in host_json["data"]["hostTbl"]:
            connected = device["active"] == "true"
            connection_type = (
                "WiFi" if "WiFi" in device["layer1interface"] else "Ethernet"
            )
            ip_address = device["ipaddress"]
            name = device["hostname"]
            mac = device["physaddress"]
            dev_type = device["type"]
            wifi = ""  # Technicolor Vodafone Station does not report wifi band

            vdf_device = VodafoneStationDevice(
                connected=connected,
                connection_type=connection_type,
                ip_address=ip_address,
                name=name,
                mac=mac,
                type=dev_type,
                wifi=wifi,
            )
            devices_dict[mac] = vdf_device

        return devices_dict

    async def get_sensor_data(self) -> dict[str, Any]:
        """Get all sensors data."""
        _LOGGER.debug("Get sensors")
        status_response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_status"
        )
        status_json = await status_response.json()
        _LOGGER.debug("GET reply (%s)", status_json)

        data = {}
        data["sys_serial_number"] = status_json["data"]["serialnumber"]
        data["sys_firmware_version"] = status_json["data"]["firmwareversion"]
        data["sys_hardware_version"] = status_json["data"]["hardwaretype"]
        data["sys_uptime"] = status_json["data"]["uptime"]
        data["wan_status"] = status_json["data"]["WANStatus"]
        data["cm_status"] = status_json["data"]["CMStatus"]
        data["lan_mode"] = status_json["data"]["LanMode"]
        return data

    async def get_docis_data(self) -> dict[str, Any]:
        """Get docis data."""
        _LOGGER.debug("Get docis data")
        response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_docsis_status"
        )
        response_json = await response.json()
        _LOGGER.debug("GET reply (%s)", response_json)

        data: dict[str, Any] = {"downstream": {}, "upstream": {}}

        # OFDM Downtream
        for channel in response_json["data"]["ofdm_downstream"]:
            data["downstream"][channel["channelid_ofdm"]] = {
                "channel_type": channel["ChannelType"],
                "channel_frequency": channel["start_frequency"],
                "channel_modulation": channel["FFT_ofdm"],
                "channel_power": channel["power_ofdm"],
                "channel_locked": channel["locked_ofdm"],
            }

        # Downtream
        for channel in response_json["data"]["downstream"]:
            data["downstream"][channel["channelid"]] = {
                "channel_type": channel["ChannelType"],
                "channel_frequency": channel["CentralFrequency"],
                "channel_modulation": channel["FFT"],
                "channel_power": channel["power"],
                "channel_locked": channel["locked"],
            }

        # OFDMA upstream
        for channel in response_json["data"]["ofdma_upstream"]:
            data["upstream"][channel["channelidup"]] = {
                "channel_type": channel["ChannelType"],
                "channel_frequency": channel["start_frequency"],
                "channel_modulation": channel["FFT"],
                "channel_power": channel["power"],
                "channel_locked": channel["RangingStatus"],
            }

        # Upstream
        for channel in response_json["data"]["upstream"]:
            data["upstream"][channel["channelidup"]] = {
                "channel_type": channel["ChannelType"],
                "channel_frequency": channel["CentralFrequency"],
                "channel_modulation": channel["FFT"],
                "channel_power": channel["power"],
                "channel_locked": channel["RangingStatus"],
            }

        data["status"] = response_json["data"]["operational"]
        return data

    async def get_voice_data(self) -> dict[str, Any]:
        """Get voice data."""
        _LOGGER.debug("Get voice data")
        response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_voice_status"
        )
        response_json = await response.json()
        _LOGGER.debug("GET reply (%s)", response_json)

        data: dict[str, Any] = {"line1": {}, "line2": {}, "general": {}}

        if "data" in response_json:
            for line in ["1", "2"]:
                if f"callnumber{line}" in response_json["data"]:
                    data[f"line{line}"] = {
                        "call_number": response_json["data"][f"callnumber{line}"],
                        "line_status": response_json["data"][f"LineStatus{line}"],
                        "status": response_json["data"][f"status{line}"],
                    }

                if "DocsisStatus" in response_json["data"]:
                    data["general"] = {
                        "status": response_json["data"]["DocsisStatus"],
                    }

        return data

    async def restart_connection(self, connection_type: str) -> None:  # noqa: ARG002
        """Internet Connection restart."""
        msg = f"Method not implemented for Technicolor device {self.base_url.host}"
        _LOGGER.error(msg)
        raise NotImplementedError(msg)

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)
        # NOTE This payload is identical to the request sent by the UI.
        payload = {
            "restart": "Router,Wifi,VoIP,Dect,MoCA",
            "ui_access": "reboot_device",
        }

        await self._request_page_result(HTTPMethod.POST, "api/v1/sta_restart", payload)

    async def logout(self) -> None:
        """Router logout."""
        _LOGGER.debug("Logout")
        await self._request_page_result(
            HTTPMethod.POST, "api/v1/session/logout", payload={}
        )

    async def ping(
        self,
        ip_address: str,
        count: int = 1,
        ping_size: int = 56,
        ping_interval: int = 1000,
        retries: int = 15,
    ) -> dict:
        """Trigger a ping diagnostic request to the router.

        Args:
        ----
            ip_address (str): The target IP address to ping.
            count (int): Number of ping requests to send (default: 1).
            ping_size (int): The size of the ping packet (default: 56 bytes).
            ping_interval (int): Interval between ping requests in milliseconds
                (default: 1000 ms).
            retries (int): Number of times to retry if results are not ready
                (default: 15).

        Returns:
        -------
            dict: The ping results.

        """
        check_url = "ping"
        data_url = "ping_res"
        key = "ping_result"
        payload = {
            "ipaddress": ip_address,
            "count": count,
            "pingsize": ping_size,
            "pingintervalin": ping_interval,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )

    async def traceroute(
        self,
        ip_address: str,
        count: int = 30,
        ip_type: str = "Ipv4",
        retries: int = 15,
    ) -> dict[str, Any]:
        """Trigger a traceroute diagnostic request to the router.

        Args:
        ----
            ip_address (str): The target IP address for the traceroute.
            count (int): Maximum number of hops (default: 30).
            ip_type (str): IP address type, either "Ipv4" or "Ipv6"
                (default: "Ipv4").
            retries (int): Number of times to retry if results are not ready
                (default: 15).

        Returns:
        -------
            dict: The traceroute results.

        """
        check_url = "traceroute"
        data_url = "traceroute_res"
        key = "traceroute_result"
        payload = {
            "traceroute_ip": ip_address,
            "count_tr": str(count),
            "ipaddresstype": ip_type,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )

    async def dns_resolve(
        self,
        hostname: str,
        dns_server: str = "1.1.1.1",
        record_type: str = "A",
        retries: int = 15,
    ) -> dict[str, Any]:
        """Trigger a traceroute diagnostic request to the router.

        Args:
        ----
            hostname (str): The hostname to resolve.
            dns_server (str): The DNS server to query (default: 1.1.1.1).
            record_type (str): DNS record type (default: "A").
            retries (int): Number of times to retry if results are not ready
                (default: 15).

        Returns:
        -------
            dict: The dns_resolve results.

        """
        check_url = "tracedns"
        data_url = "traceDns_res"
        # The result field is named "traceroute_result"
        # this is not a typo
        key = "traceroute_result"
        payload = {
            "tracednsip": dns_server,
            "tracednsName": hostname,
            "qtype": record_type,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )


class VodafoneStationSercommApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Sercomm firmware."""

    async def _list_2_dict(self, data: dict[dict[str, Any], Any]) -> dict[str, Any]:
        """Transform list in a dict."""
        kv_tuples = [((next(iter(v.keys()))), (next(iter(v.values())))) for v in data]
        key_values = {}
        for entry in kv_tuples:
            key_values[entry[0]] = entry[1]

        _LOGGER.debug("Data retrieved (key_values): %s", key_values)
        return key_values

    async def _get_sercomm_page(self, page: str) -> dict[str, Any]:
        """Get html page and process reply."""
        reply = await self._request_page_result(HTTPMethod.GET, page)
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("GET reply (%s): %s", page, reply_json)
        return await self._list_2_dict(reply_json)

    async def _post_sercomm_page(
        self,
        page: str,
        payload: dict[str, Any],
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> dict[Any, Any] | str:
        """Post html page and process reply."""
        reply = await self._request_page_result(HTTPMethod.POST, page, payload, timeout)
        _LOGGER.debug("POST raw reply (%s): %s", page, await reply.text())
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("POST json reply (%s): %s", page, reply_json)
        return cast("dict", reply_json)

    async def _check_logged_in(self) -> bool:
        """Check if logged in or not."""
        reply = await self._post_sercomm_page(
            "data/login.json",
            {"loginUserChkLoginTimeout": self.username},
        )
        index = int(str(reply)) if reply else 0
        _LOGGER.debug("Login status: %s[%s]", DEVICE_SERCOMM_LOGIN_STATUS[index], reply)
        return bool(reply)

    async def _get_csrf_token(self, reply_text: str) -> None:
        """Load login page to get csrf token."""
        soup = BeautifulSoup(reply_text, "html.parser")
        script_tags = [
            tag for tag in soup.find_all("script") if tag.get_text(strip=True)
        ]
        try:
            # Concatenate all script content to search for token
            scripts_text = " ".join(tag.get_text() for tag in script_tags)
            token = re.findall("(?<=csrf_token)|[^']+", scripts_text)[1]
        except IndexError as err:
            raise ModelNotSupported from err
        if not token:
            return
        self.csrf_token = token
        _LOGGER.debug("csrf_token: <%s>", self.csrf_token)

    async def _get_user_lang(self) -> None:
        """Load user_lang page to get."""
        return_dict = await self._get_sercomm_page("data/user_lang.json")
        self.encryption_key = return_dict["encryption_key"]
        _LOGGER.debug("encryption_key: <%s>", self.encryption_key)

    async def _encrypt_string(self, credential: str) -> str:
        """Encrypt username or password for login."""
        hash1_str = hmac.new(
            bytes("$1$SERCOMM$", "latin-1"),
            msg=bytes(credential, "latin-1"),
            digestmod=hashlib.sha256,
        ).hexdigest()

        return hmac.new(
            bytes(self.encryption_key, "latin-1"),
            msg=bytes(hash1_str, "latin-1"),
            digestmod=hashlib.sha256,
        ).hexdigest()

    async def _encrypt_with_challenge(self, challenge: str) -> str:
        """Encrypt password with challenge for login."""
        return hashlib.sha256(
            bytes(self.password + challenge, "utf-8"),
        ).hexdigest()

    async def _get_challenge(self) -> str:
        """Return challenge or login."""
        return_dict = await self._get_sercomm_page("data/login.json")
        challenge: str = return_dict["challenge"]
        _LOGGER.debug("challenge: <%s>", challenge)
        return challenge

    async def _reset(self) -> bool:
        """Reset page content before loading."""
        payload = {"chk_sys_busy": ""}
        reply = await self._request_page_result(
            HTTPMethod.POST, "data/reset.json", payload
        )
        if isinstance(reply, ClientResponse):
            return bool(reply.status == HTTPStatus.OK)

        return False

    async def _login_json(self, payload: dict[str, Any]) -> bool:
        """Login via json page."""
        reply_json = await self._post_sercomm_page("data/login.json", payload)
        reply_str = str(reply_json)
        if not reply_str.isdigit():
            raise GenericResponseError(f"Unexpected login response: {reply_str}")

        _LOGGER.debug(
            "Login result: %s[%s]",
            DEVICE_SERCOMM_LOGIN_STATUS[int(reply_str)]
            if 0 <= int(reply_str) < len(DEVICE_SERCOMM_LOGIN_STATUS)
            else "unknown",
            reply_json,
        )

        if reply_str == "1":
            return True

        if reply_str == "2":
            raise AlreadyLogged

        if reply_str in ["3", "4", "5", "7"]:
            raise CannotAuthenticate

        raise GenericLoginError

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert router uptime to last boot datetime."""
        d = int(uptime.split(":")[0])
        h = int(uptime.split(":")[1])
        m = int(uptime.split(":")[2])

        return datetime.now(tz=UTC) - timedelta(
            days=d,
            hours=h,
            minutes=m,
        )

    async def login(self, force_logout: bool = False) -> bool:  # noqa: ARG002
        """Router login."""
        _LOGGER.debug("Logging into %s", self.base_url.host)
        try:
            reply = await self._request_page_result(
                HTTPMethod.GET, DEVICE_SERCOMM_LOGIN_URL
            )
        except (asyncio.exceptions.TimeoutError, ClientConnectorError) as exc:
            _LOGGER.warning("Connection error for %s", self.base_url.host)
            raise CannotConnect from exc

        await self._get_csrf_token(await reply.text())
        await self._get_user_lang()
        await self._set_cookie()
        await self._reset()

        if not self.encryption_key:
            _LOGGER.debug("Login: username[plain], password[challenge encrypted]")

            challenge = await self._get_challenge()
            logged = await self._login_json(
                {
                    "LoginName": self.username,
                    "LoginPWD": await self._encrypt_with_challenge(challenge),
                    "challenge": challenge,
                },
            )
        else:
            # First  try with both  username and password encrypted
            # Second try with plain username and password encrypted
            try:
                _LOGGER.debug(
                    "Login first try: username[encrypted], password[encrypted]",
                )
                logged = await self._login_json(
                    {
                        "LoginName": await self._encrypt_string(self.username),
                        "LoginPWD": await self._encrypt_string(self.password),
                    },
                )
            except CannotAuthenticate:
                _LOGGER.debug("Login second try: username[plain], password[encrypted]")
                logged = await self._login_json(
                    {
                        "LoginName": self.username,
                        "LoginPWD": await self._encrypt_string(self.password),
                    },
                )

        return logged

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get all connected devices."""
        _LOGGER.debug("Getting all devices for host %s", self.base_url.host)
        return_dict = await self._get_sercomm_page("data/overview.json")

        # Cleanup sensor data from devices in order to be merged later
        self._overview.update(return_dict)
        for info in ["wifi_user", "wifi_guest", "ethernet"]:
            if info in self._overview:
                self._overview.pop(info)

        if (
            "wifi_user" not in return_dict
            and "wifi_guest" not in return_dict
            and "ethernet" not in return_dict
        ):
            _LOGGER.info("No device in response from %s", self.base_url.host)
            return self._devices

        _arr_devices: list[list[str]] = []
        # Wifi user
        arr_wifi_user_list: list[str] = return_dict["wifi_user"].split(";")
        arr_wifi_user_filter: filter[str] = filter(
            lambda x: x.strip() != "", arr_wifi_user_list
        )
        arr_wifi_user = ["Wifi (Main)|" + dev for dev in arr_wifi_user_filter]
        _arr_devices.append(arr_wifi_user)
        # Wifi guest
        arr_wifi_guest_list: list[str] = return_dict["wifi_guest"].split(";")
        arr_wifi_guest_filter: filter[str] = filter(
            lambda x: x.strip() != "", arr_wifi_guest_list
        )
        arr_wifi_guest = ["[Wifi (Guest)|" + dev for dev in arr_wifi_guest_filter]
        _arr_devices.append(arr_wifi_guest)
        # Ethernet
        arr_ethernet_list: list[str] = return_dict["ethernet"].split(";")
        arr_ethernet_filter: filter[str] = filter(
            lambda x: x.strip() != "", arr_ethernet_list
        )
        arr_ethernet = ["Ethernet|on|" + dev + "|||" for dev in arr_ethernet_filter]
        _arr_devices.append(arr_ethernet)
        arr_devices: list[str] = [item for sublist in _arr_devices for item in sublist]
        _LOGGER.debug("Array of devices: %s", arr_devices)

        for device_line in arr_devices:
            device_fields: list[str] = device_line.split("|")
            wifi_band = (
                device_fields[7]
                if len(device_fields) == DEVICE_SERCOMM_TOTAL_FIELDS_NUM
                else ""
            )
            try:
                dev_info = VodafoneStationDevice(
                    connection_type=device_fields[0],
                    connected=device_fields[1] == "on",
                    type=device_fields[2],
                    name=device_fields[3],
                    mac=device_fields[4],
                    ip_address=device_fields[5],
                    wifi=wifi_band,
                )
                self._devices[dev_info.mac] = dev_info
            except (KeyError, IndexError):
                _LOGGER.warning("Error processing line: %s", device_line)

        return self._devices

    async def get_sensor_data(self) -> dict[str, Any]:
        """Load user_data page information."""
        _LOGGER.debug("Getting sensor data for host %s", self.base_url.host)

        reply_dict_1 = await self._get_sercomm_page("data/user_data.json")
        reply_dict_2 = await self._get_sercomm_page("data/statussupportstatus.json")
        reply_dict_3 = await self._get_sercomm_page("data/statussupportrestart.json")

        return reply_dict_1 | reply_dict_2 | reply_dict_3 | self._overview

    async def get_docis_data(self) -> dict[str, Any]:
        """Get docis data."""
        return {}

    async def get_voice_data(self) -> dict[str, Any]:
        """Get voice data."""
        return {}

    async def logout(self) -> None:
        """Router logout."""
        if hasattr(self, "session"):
            self.session.cookie_jar.clear()

    async def restart_connection(self, connection_type: str) -> None:
        """Internet Connection restart."""
        _LOGGER.debug(
            "Restarting %s connection for router %s",
            connection_type,
            self.base_url.host,
        )
        payload = {f"{connection_type}_reconnect": "1"}
        try:
            if not await self._check_logged_in():
                await self.login()
            await self._post_sercomm_page("data/statussupportrestart.json", payload)
        except ClientResponseError as ex:
            _LOGGER.debug(
                'Client response error for "restart_connection" is: %s',
                ex.message,
            )
            # Some models dump a text reply with wrong HTML headers
            # as reply to a reconnection request
            if not ex.message.startswith("Invalid header token"):
                raise

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)
        payload = {"restart_device": "1"}
        try:
            if not await self._check_logged_in():
                await self.login()
            await self._request_page_result(
                HTTPMethod.POST,
                "data/statussupportrestart.json",
                payload,
                POST_RESTART_TIMEOUT,
            )
        except asyncio.exceptions.TimeoutError:
            pass


class VodafoneStationUltraHubApi(VodafoneStationCommonApi):
    """Queries Vodafone Ultra Hub."""

    def __init__(
        self, url: URL, username: str, password: str, session: ClientSession
    ) -> None:
        """Initialize id as it may change in the future."""
        super().__init__(url, username, password, session)
        self.id = "3"

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.base_url.host)

        if not force_logout:
            self.session.cookie_jar.clear()
            self.session.cookie_jar.update_cookies(
                SimpleCookie(
                    f"domain={self.base_url.host}; HttpOnly; Path=/; SameSite=Lax;"
                ),
            )

            self.csrf_token = ""

            reply = await self._auto_hub_request_page_result(
                HTTPMethod.GET,
                "/api/config/details.jst",
                params={"X_INTERNAL_FIELDS": "X_RDK_ONT_Veip_1_OperationalState"},
            )

            reply_json = await reply.json()

            if "X_INTERNAL_ID" in reply_json:
                self.id = reply_json["X_INTERNAL_ID"]
                self.session.cookie_jar.update_cookies(reply.cookies)

        if self.csrf_token == "":
            raise CannotAuthenticate

        reply = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            "/api/users/details.jst",
            params={"__id": self.id, "X_INTERNAL_FIELDS": "X_VODAFONE_WebUISecret"},
        )

        reply_json = await reply.json()

        if "X_VODAFONE_WebUISecret" in reply_json:
            web_secret = reply_json["X_VODAFONE_WebUISecret"]
            salt_web_ui = web_secret[:10]
            salt = web_secret[10:]
            password = await self._encrypt_string(salt, salt_web_ui)
            payload = {
                "__id": self.id,
                "X_VODAFONE_Password": password,
                "Push": str(force_logout).lower(),
                "csrf_token": self.csrf_token,
            }

            reply = await self._auto_hub_request_page_result(
                HTTPMethod.POST,
                "api/users/login.jst",
                payload=payload,
            )

            self.session.cookie_jar.update_cookies(reply.cookies)
            reply_json = await reply.json()

            if (
                "X_INTERNAL_Password_Status" in reply_json
                and reply_json["X_INTERNAL_Password_Status"] == "Invalid_PWD"  # noqa: S105
            ):
                raise CannotAuthenticate

            if (
                "X_INTERNAL_Is_Duplicate" in reply_json
                and reply_json["X_INTERNAL_Is_Duplicate"] == "true"
                and not force_logout
            ):
                raise AlreadyLogged

            return True

        raise GenericLoginError

    async def _encrypt_string(
        self,
        salt: str,
        salt_web_ui: str,
    ) -> str:
        """Calculate login hash (password), the salt and the salt (web UI).

        Args:
        ----
            salt (str): salt given by the login response
            salt_web_ui (str): salt given by the web UI

        Returns:
        -------
            str: the hash for the session API

        """
        _LOGGER.debug("Calculate credential hash")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=bytes(salt, "utf-8"),
            iterations=1000,
        )

        key = kdf.derive(bytes(salt_web_ui, "utf-8"))

        iv = os.urandom(16)
        nonce = self._truncate_iv(iv, len(self.password) * 8, 8)
        aesccm = AESCCM(key, 8)
        ct = aesccm.encrypt(nonce, bytes(self.password, "utf-8"), None)
        b64_ct = base64.b64encode(ct).decode("ascii").strip()
        b64_iv = base64.b64encode(iv).decode("ascii").strip()

        value = '{"iv":"'
        value += b64_iv
        value += '","v":1,"iter":10000,"ks":128,"ts":64,"mode":"ccm",'
        value += '"adata":"","cipher":"aes","ct":"'
        value += b64_ct
        value += '"}'
        return value

    def _truncate_iv(
        self,
        iv: bytes,
        ol: int,  # in bytes
        tlen: int,  # in bytes
    ) -> bytes:
        """Calculate the nonce as it can not be 16 bytes."""
        ivl = len(iv)  # iv length in bytes
        ol = (ol - tlen) // 8

        # "compute the length of the length" (see ccm.js)
        loop = 2
        dumb_constant_to_keep_ruff_happy = 4
        while (loop < dumb_constant_to_keep_ruff_happy) and (ol >> (8 * loop)) > 0:
            loop += 1
            loop = max(loop, 15 - ivl)

        return iv[: (15 - loop)]

    async def _auto_hub_request_page_result(
        self,
        method: str,
        page: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> ClientResponse:
        """Request data from a web page."""
        url = f"{self.base_url}{page}"
        _LOGGER.debug("%s page %s", method, url)

        try:
            response = await self.session.request(
                method,
                url,
                params=params,
                data=payload,
                headers=self.headers,
                allow_redirects=False,
                timeout=timeout,
                ssl=False,
            )
            if (
                response.status != HTTPStatus.OK
                and response.content_type == "application/json"
            ):
                _LOGGER.warning(
                    "%s page %s failed: %s",
                    method,
                    url,
                    response.status,
                )
                raise GenericResponseError
        except ClientResponseError as err:
            _LOGGER.exception(
                "%s page %s from host %s failed", method, page, self.base_url.host
            )
            raise GenericResponseError from err
        else:
            reply_json = await response.json()
            """So we do not have to play whack a mole for the csrf_token"""
            if "csrf_token" in reply_json:
                self.csrf_token = reply_json["csrf_token"]

            return response

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert uptime to datetime."""
        return datetime.now(tz=UTC) - timedelta(
            seconds=int(uptime),
        )

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get router device data."""
        _LOGGER.debug("Get hosts")

        devices_dict = {}

        reply = await self._auto_hub_request_page_result(
            HTTPMethod.GET, "/api/device/bulk/details.jst"
        )

        reply_json = await reply.json()

        if "hosts" in reply_json:
            hosts = reply_json["hosts"]
            for device in hosts:
                connected = device["Active"] == "true"
                connection_type = (
                    "WiFi" if "WiFi" in device["Layer1Interface"] else "Ethernet"
                )
                ip_address = device["IPv4Address_1_IPAddress"]
                name = device["HostName"]
                mac = device["PhysAddress"]
                dev_type = device["X_VODAFONE_Fingerprint_Class"]
                wifi = device["X_CISCO_COM_RSSI"]

                vdf_device = VodafoneStationDevice(
                    connected=connected,
                    connection_type=connection_type,
                    ip_address=ip_address,
                    name=name,
                    mac=mac,
                    type=dev_type,
                    wifi=wifi,
                )
                devices_dict[mac] = vdf_device

        return devices_dict

    async def get_sensor_data(self) -> dict[str, Any]:
        """Get router sensor data."""
        reply = await self._auto_hub_request_page_result(
            HTTPMethod.GET, "/api/device/details.jst"
        )

        reply_json = await reply.json()

        data = {}

        data["sys_firmware_version"] = reply_json["SoftwareVersion"]
        data["sys_hardware_version"] = reply_json["HardwareVersion"]
        data["sys_serial_number"] = reply_json["SerialNumber"]
        data["sys_uptime"] = reply_json["UpTime"]
        data["wan_status"] = ""
        data["cm_status"] = ""
        data["lan_mode"] = reply_json["X_VODAFONE_WANType"]

        interface = reply_json["INTERNAL_CPEInterface_List"]
        for device in interface:
            if device["DisplayName"] == "WWAN":
                data["wan_status"] = device["Phy_Status"]
            if device["DisplayName"] == "WANoE":
                data["cm_status"] = device["Phy_Status"]

        return data

    async def get_docis_data(self) -> dict[str, Any]:
        """Get router docis data."""
        return {}

    async def get_voice_data(self) -> dict[str, Any]:
        """Get router voice data."""
        return {}

    async def restart_connection(self, connection_type: str) -> None:  # noqa: ARG002
        """Internet Connection restart."""
        msg = f"Method not implemented for UltraHub device {self.base_url.host}"
        _LOGGER.error(msg)
        raise NotImplementedError(msg)

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)

        payload = {"RebootDevice": "true", "csrf_token": self.csrf_token}

        with contextlib.suppress(GenericResponseError):
            await self._auto_hub_request_page_result(
                HTTPMethod.POST, "api/device/update.jst", payload=payload
            )

        self.csrf_token = ""
        self.session.cookie_jar.clear()

    async def logout(self) -> None:
        """Router logout."""
        _LOGGER.debug("Log out of router %s", self.base_url.host)
        if hasattr(self, "session") and self.csrf_token is not None:
            payload = {"__id": self.id, "csrf_token": self.csrf_token}

            with contextlib.suppress(GenericResponseError):
                await self._auto_hub_request_page_result(
                    HTTPMethod.POST, "api/users/logout.jst", payload=payload
                )

            self.csrf_token = ""
            self.session.cookie_jar.clear()


def init_api_class(
    url: URL, device_type: str, data: Mapping[str, Any], session: ClientSession
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


class_registry: dict[str, type[VodafoneStationCommonApi]] = {
    "Sercomm": VodafoneStationSercommApi,
    "Technicolor": VodafoneStationTechnicolorApi,
    "Ultrahub": VodafoneStationUltraHubApi,
}
