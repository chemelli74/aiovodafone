"""Support for Vodafone Station."""

import asyncio
import hashlib
import hmac
import re
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from http.cookies import SimpleCookie
from typing import Any, cast

from aiohttp import (
    ClientConnectorError,
    ClientConnectorSSLError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    CookieJar,
)
from bs4 import BeautifulSoup, Tag

from .const import (
    _LOGGER,
    FULL_FIELDS_NUM,
    HEADERS,
    LOGIN,
    USER_ALREADY_LOGGED_IN,
    DeviceType,
)
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    ModelNotSupported,
    RequestFailed,
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
    ) -> DeviceType | None:
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
            DeviceType:
            If the device is a Technicolor, it returns `DeviceType.TECHNICOLOR`.
            If the device is a Sercomm,     it returns `DeviceType.SERCOMM`.
            If neither of the device types match, it returns `None`.

        """
        async with session.get(
            f"http://{host}/api/v1/login_conf",
            headers=HEADERS,
        ) as response:
            if response.status == HTTPStatus.OK:
                response_json = await response.json()
                if "data" in response_json and "ModelName" in response_json["data"]:
                    return DeviceType.TECHNICOLOR

        for protocol in ["https", "http"]:
            try:
                async with session.get(
                    f"{protocol}://{host}/login.html",
                    headers=HEADERS,
                    ssl=False,
                ) as response:
                    # To identify the Sercomm devices before the login
                    # There's no other sure way to identify a Sercomm device
                    # without login
                    if (
                        response.status == HTTPStatus.OK
                        and "var csrf_token = " in await response.text()
                    ):
                        return DeviceType.SERCOMM
            except ClientConnectorSSLError:
                _LOGGER.debug("Unable to login using protocol %s", protocol)
                continue

        return None

    def __init__(self, host: str, username: str, password: str) -> None:
        """Initialize the scanner."""
        self.host = host
        self.protocol = "http"
        self.username = username
        self.password = password
        self.base_url = self._base_url()
        self.headers = HEADERS
        self.session: ClientSession
        self.csrf_token: str = ""
        self.encryption_key: str = ""
        self._unique_id: str | None = None
        self._overview: dict[str, Any] = {}
        self._devices: dict[str, VodafoneStationDevice] = {}

    def _client_session(self) -> None:
        """Create aiohttp ClientSession."""
        if not hasattr(self, "session") or self.session.closed:
            _LOGGER.debug("Creating HTTP ClientSession")
            jar = CookieJar(unsafe=True)
            self.session = ClientSession(cookie_jar=jar)

    def _base_url(self) -> str:
        """Create base URL."""
        return f"{self.protocol}://{self.host}"

    async def _set_cookie(self) -> None:
        """Enable required session cookie."""
        self.session.cookie_jar.update_cookies(
            SimpleCookie(f"domain={self.host}; name=login_uid; value=1;"),
        )

    async def _post_page_result(
        self,
        page: str,
        payload: dict[str, Any],
        timeout: int = 10,
    ) -> ClientResponse:
        """Get data from a web page via POST."""
        _LOGGER.debug("POST page  %s from host %s", page, self.host)
        timestamp = int(datetime.now(tz=UTC).timestamp())
        url = f"{self.base_url}{page}?_={timestamp}&csrf_token={self.csrf_token}"
        return await self.session.post(
            url,
            data=payload,
            headers=self.headers,
            timeout=timeout,
            ssl=False,
            allow_redirects=True,
        )

    async def _get_page_result(self, page: str) -> ClientResponse:
        """Get data from a web page via GET."""
        _LOGGER.debug("GET page  %s [%s]", page, self.host)
        timestamp = int(datetime.now(tz=UTC).timestamp())
        url = f"{self.base_url}{page}?_={timestamp}&csrf_token={self.csrf_token}"

        return await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=False,
        )

    async def close(self) -> None:
        """Router close session."""
        if hasattr(self, "session"):
            await self.session.close()

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
    async def get_sensor_data(self) -> dict[Any, Any]:
        """Get router sensor data."""

    @abstractmethod
    async def get_docis_data(self) -> dict[Any, Any]:
        """Get router docis data."""

    @abstractmethod
    async def get_voice_data(self) -> dict[Any, Any]:
        """Get router voice data."""

    @abstractmethod
    async def logout(self) -> None:
        """Router logout."""

    @abstractmethod
    async def traceroute(
        self,
        ip_address: str,
        count: int = 30,
        ip_type: str = "Ipv4",
        retries: int = 15,
    ) -> dict:
        """Traceroute."""

    @abstractmethod
    async def ping(
        self,
        ip_address: str,
        count: int = 1,
        ping_size: int = 56,
        ping_interval: int = 1000,
        retries: int = 15,
    ) -> dict:
        """Ping."""

    @abstractmethod
    async def dns_resolve(
        self,
        hostname: str,
        dns_server: str = "1.1.1.1",
        record_type: str = "A",
        retries: int = 15,
    ) -> dict:
        """DNS Test."""


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

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s (force: %s)", self.host, force_logout)
        self._client_session()

        _LOGGER.debug("Get salt for login")
        payload = {"username": self.username, "password": "seeksalthash"}
        salt_response = await self._post_page_result(
            page="/api/v1/session/login",
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
        login_response = await self._post_page_result(
            page="/api/v1/session/login",
            payload=payload,
        )
        login_json = await login_response.json()
        if "error" in login_json and login_json["error"] == "error":
            if login_json["message"] == USER_ALREADY_LOGGED_IN:
                raise AlreadyLogged
            _LOGGER.error(login_json)
            raise CannotAuthenticate

        # Request menu otherwise the next call fails
        _LOGGER.debug("Get menu")
        await self._get_page_result("/api/v1/session/menu")

        return True

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get all connected devices as a map of MAC address and device object.

        Returns
        -------
            dict[str, VodafoneStationDevice]: MAC address maps to VodafoneStationDevice

        """
        _LOGGER.debug("Get hosts")
        host_response = await self._get_page_result("/api/v1/host/hostTbl")
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

    async def get_sensor_data(self) -> dict[Any, Any]:
        """Get all sensors data."""
        _LOGGER.debug("Get sensors")
        status_response = await self._get_page_result("/api/v1/sta_status")
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

    async def get_docis_data(self) -> dict[Any, Any]:
        """Get docis data."""
        _LOGGER.debug("Get docis data")
        response = await self._get_page_result("/api/v1/sta_docsis_status")
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

    async def get_voice_data(self) -> dict[Any, Any]:
        """Get voice data."""
        _LOGGER.debug("Get voice data")
        response = await self._get_page_result("/api/v1/sta_voice_status")
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

    async def logout(self) -> None:
        """Router logout."""
        _LOGGER.debug("Logout")
        await self._post_page_result("/api/v1/session/logout", payload={})

    async def _post_page_result_with_handling(
        self,
        endpoint: str,
        payload: dict,
        timeout: int = 10,
    ) -> aiohttp.ClientResponse | None:
        """Wrap `_post_page_result` to handle errors and logging.

        Args:
        ----
            endpoint (str): API endpoint for the POST request.
            payload (dict): Data to be sent in the POST request.
            timeout (int): Timeout for the request (default: 10 seconds).

        Returns:
        -------
            aiohttp.ClientResponse | None: The response object if successful,
            None otherwise.

        """
        try:
            return await self._post_page_result(endpoint, payload, timeout)
        except aiohttp.ClientResponseError:
            _LOGGER.exception("Request to %s failed", endpoint)
        return None

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
            bool: The ping results.

        """
        url = "/api/v1/sta_diagnostic_utility/ping"
        async with await self._get_page_result(url) as csrf_res:
            csrf_json = await csrf_res.json()
        _LOGGER.debug("CSRF response (see token): %s", csrf_json)
        token = csrf_json.get("token")
        if token:
            self.headers["X-CSRF-Token"] = token
        else:
            _LOGGER.warning("Failed to retrieve CSRF token")

        payload = {
            "ipaddress": ip_address,
            "count": count,
            "pingsize": ping_size,
            "pingintervalin": ping_interval,
        }

        response = await self._post_page_result_with_handling(
            url,
            payload,
        )
        if response is None or response.status != HTTPStatus.OK:
            raise RequestFailed("Failed to trigger ping request.")

        for attempt in range(retries):
            try:
                result = await self.get_ping_results()
                if result and result.get("data", {}).get("ping_result") != "InProgress":
                    return result

                _LOGGER.debug(
                    "Ping results not ready, retrying (%d/%d)...",
                    attempt + 1,
                    retries,
                )
                # sleep for 2 seconds, just like the dashboard does
                await asyncio.sleep(2)
            except aiohttp.ClientResponseError:
                _LOGGER.exception("Failed to retrieve ping results")

        raise ResultTimeoutError(
            "ping results not available after %d retries",
            retries,
        )

    async def get_ping_results(self) -> dict[Any, Any] | None:
        """Retrieve the results of the ping diagnostic.

        Returns
        -------
            dict | None: The ping results if available, None otherwise.

        """
        try:
            response = await self._get_page_result(
                "/api/v1/sta_diagnostic_utility/ping_res",
            )

            if response.status == HTTPStatus.OK:
                json_data: dict[Any, Any] = await response.json()
                return json_data
        except aiohttp.ClientResponseError:
            _LOGGER.exception("Failed to retrieve ping results")

        return None

    async def traceroute(
        self,
        ip_address: str,
        count: int = 30,
        ip_type: str = "Ipv4",
        retries: int = 15,
    ) -> dict:
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
        url = "/api/v1/sta_diagnostic_utility/traceroute"
        async with await self._get_page_result(url) as csrf_res:
            csrf_json = await csrf_res.json()
        _LOGGER.debug("CSRF response (see token): %s", csrf_json)
        token = csrf_json.get("token")
        if token:
            self.headers["X-CSRF-Token"] = token
        else:
            _LOGGER.warning("Failed to retrieve CSRF token")

        payload = {
            "traceroute_ip": ip_address,
            "count_tr": str(count),
            "ipaddresstype": ip_type,
        }

        response = await self._post_page_result_with_handling(url, payload)
        if response is None or response.status != HTTPStatus.OK:
            raise RequestFailed("Failed to trigger traceroute request.")

        for attempt in range(retries):
            try:
                result = await self.get_traceroute_results()
                if (
                    result
                    and result.get("data", {}).get("traceroute_result") != "InProgress"
                ):
                    return result

                _LOGGER.debug(
                    "Traceroute results not ready, retrying (%d/%d)...",
                    attempt + 1,
                    retries,
                )
                # sleep for 2 seconds, just like the dashboard does
                await asyncio.sleep(2)
            except aiohttp.ClientResponseError:
                _LOGGER.exception("Failed to retrieve traceroute results")

        raise ResultTimeoutError(
            "traceroute results not available after %d retries",
            retries,
        )

    async def get_traceroute_results(self) -> dict[Any, Any] | None:
        """Retrieve the results of the traceroute diagnostic.

        Returns
        -------
            dict | None: The traceroute results if available, None otherwise.

        """
        try:
            response = await self._get_page_result(
                "/api/v1/sta_diagnostic_utility/traceroute_res",
            )

            if response.status == HTTPStatus.OK:
                json_data: dict[Any, Any] = await response.json()
                return json_data
        except aiohttp.ClientResponseError:
            _LOGGER.exception("Failed to retrieve traceroute results")

        return None

    async def dns_resolve(
        self,
        hostname: str,
        dns_server: str = "1.1.1.1",
        record_type: str = "A",
        retries: int = 15,
    ) -> dict:
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
        url = "/api/v1/sta_diagnostic_utility/tracedns"
        async with await self._get_page_result(url) as csrf_res:
            csrf_json = await csrf_res.json()
        _LOGGER.debug("CSRF response (see token): %s", csrf_json)
        token = csrf_json.get("token")
        if token:
            self.headers["X-CSRF-Token"] = token
        else:
            _LOGGER.warning("Failed to retrieve CSRF token")

        payload = {
            "tracednsip": dns_server,
            "tracednsName": hostname,
            "qtype": record_type,
        }

        response = await self._post_page_result_with_handling(url, payload)
        if response is None or response.status != HTTPStatus.OK:
            raise RequestFailed("Failed to trigger traceroute request.")

        for attempt in range(retries):
            try:
                result = await self.get_dns_resolve_results()
                if (
                    result
                    # NOTE Yes, the result field is named "traceroute_result",
                    # this is not a typo
                    and result.get("data", {}).get("traceroute_result") != "InProgress"
                ):
                    return result

                _LOGGER.debug(
                    "DNS resolve results not ready, retrying (%d/%d)...",
                    attempt + 1,
                    retries,
                )
                # sleep for 2 seconds, just like the dashboard does
                await asyncio.sleep(2)
            except aiohttp.ClientResponseError:
                _LOGGER.exception("Failed to retrieve dns_resolve results")

        raise ResultTimeoutError(
            "dns results not available after %d retries",
            retries,
        )

    async def get_dns_resolve_results(self) -> dict[Any, Any] | None:
        """Retrieve the results of the dns_resolve diagnostic.

        Returns
        -------
            dict | None: The DNS resolve results if available, None otherwise.

        """
        try:
            response = await self._get_page_result(
                "/api/v1/sta_diagnostic_utility/traceDns_res",
            )

            if response.status == HTTPStatus.OK:
                json_data: dict[Any, Any] = await response.json()
                return json_data
        except aiohttp.ClientResponseError:
            _LOGGER.exception("Failed to retrieve DNS resolve results")

        return None


class VodafoneStationSercommApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Sercomm firmware."""

    async def _list_2_dict(self, data: dict[Any, Any]) -> dict[Any, Any]:
        """Transform list in a dict."""
        kv_tuples = [((next(iter(v.keys()))), (next(iter(v.values())))) for v in data]
        key_values = {}
        for entry in kv_tuples:
            key_values[entry[0]] = entry[1]

        _LOGGER.debug("Data retrieved (key_values): %s", key_values)
        return key_values

    async def _get_sercomm_page(self, page: str) -> dict[Any, Any]:
        """Get html page and process reply."""
        reply = await self._get_page_result(page)
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("GET reply (%s): %s", page, reply_json)
        return await self._list_2_dict(reply_json)

    async def _post_sercomm_page(
        self,
        page: str,
        payload: dict[str, Any],
        timeout: int = 10,
    ) -> dict[Any, Any] | str:
        """Post html page and process reply."""
        reply = await self._post_page_result(page, payload, timeout)
        _LOGGER.debug("POST raw reply (%s): %s", page, await reply.text())
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("POST json reply (%s): %s", page, reply_json)
        return cast("dict", reply_json)

    async def _check_logged_in(self) -> bool:
        """Check if logged in or not."""
        reply = await self._post_sercomm_page(
            "/data/login.json",
            {"loginUserChkLoginTimeout": self.username},
        )
        index = int(str(reply)) if reply else 0
        _LOGGER.debug("Login status: %s[%s]", LOGIN[index], reply)
        return bool(reply)

    async def _find_login_url(self) -> str:
        """Find the login page.

        Router reply with 200 and a html body instead of a formal redirect
        """
        url = f"{self.base_url}/login.html"
        _LOGGER.debug("Requested login url: <%s>", url)
        reply = await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=True,
        )
        if reply.status in [HTTPStatus.FORBIDDEN, HTTPStatus.NOT_FOUND]:
            raise ModelNotSupported
        reply_text = await reply.text()
        soup = BeautifulSoup(reply_text, "html.parser")
        meta_refresh = soup.find("meta", {"http-equiv": "Refresh"})
        if isinstance(meta_refresh, Tag) and "content" in meta_refresh.attrs:
            meta_content = meta_refresh.get("content")
            parsed_qs = urllib.parse.parse_qs(str(meta_content), separator="; ")
            reply_url: str = parsed_qs["URL"][0]
            redirect_url = urllib.parse.urlparse(reply_url)
            if redirect_url.scheme != self.protocol:
                self.protocol = redirect_url.scheme
                self.base_url = self._base_url()
                _LOGGER.debug("Redirected login!")
                reply_text = await self._find_login_url()

        return cast("str", reply_text)

    async def _get_csrf_token(self, reply_text: str) -> None:
        """Load login page to get csrf token."""
        soup = BeautifulSoup(reply_text, "html.parser")
        script_tag = soup.find("script", string=True)
        try:
            token = re.findall("(?<=csrf_token)|[^']+", str(script_tag))[1]
        except IndexError as err:
            raise ModelNotSupported from err
        if not token:
            return
        self.csrf_token = token
        _LOGGER.debug("csrf_token: <%s>", self.csrf_token)

    async def _get_user_lang(self) -> None:
        """Load user_lang page to get."""
        return_dict = await self._get_sercomm_page("/data/user_lang.json")
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
        return_dict = await self._get_sercomm_page("/data/login.json")
        challenge: str = return_dict["challenge"]
        _LOGGER.debug("challenge: <%s>", challenge)
        return challenge

    async def _reset(self) -> bool:
        """Reset page content before loading."""
        payload = {"chk_sys_busy": ""}
        reply = await self._post_page_result("/data/reset.json", payload)
        if isinstance(reply, ClientResponse):
            return bool(reply.status == HTTPStatus.OK)

        return False

    async def _login_json(self, payload: dict[str, Any]) -> bool:
        """Login via json page."""
        reply_json = await self._post_sercomm_page("/data/login.json", payload)
        reply_str = str(reply_json)
        _LOGGER.debug(
            "Login result: %s[%s]",
            LOGIN[int(reply_str)] if 0 <= int(reply_str) < len(LOGIN) else "unknown",
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
        _LOGGER.debug("Logging into %s", self.host)
        try:
            self._client_session()
            html_page = await self._find_login_url()
        except (asyncio.exceptions.TimeoutError, ClientConnectorError) as exc:
            _LOGGER.warning("Connection error for %s", self.host)
            raise CannotConnect from exc

        await self._get_csrf_token(html_page)
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
        _LOGGER.debug("Getting all devices for host %s", self.host)
        return_dict = await self._get_sercomm_page("/data/overview.json")

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
            _LOGGER.info("No device in response from %s", self.host)
            return self._devices

        arr_devices = []
        arr_wifi_user = return_dict["wifi_user"].split(";")
        arr_wifi_user = filter(lambda x: x.strip() != "", arr_wifi_user)
        arr_wifi_user = ["Wifi (Main)|" + dev for dev in arr_wifi_user]
        arr_wifi_guest = return_dict["wifi_guest"].split(";")
        arr_wifi_guest = filter(lambda x: x.strip() != "", arr_wifi_guest)
        arr_wifi_guest = ["[Wifi (Guest)|" + dev for dev in arr_wifi_guest]
        arr_devices.append(arr_wifi_user)
        arr_devices.append(arr_wifi_guest)
        arr_ethernet = return_dict["ethernet"].split(";")
        arr_ethernet = filter(lambda x: x.strip() != "", arr_ethernet)
        arr_ethernet = ["Ethernet|on|" + dev + "|||" for dev in arr_ethernet]
        arr_devices.append(arr_ethernet)
        arr_devices = [item for sublist in arr_devices for item in sublist]
        _LOGGER.debug("Array of devices: %s", arr_devices)

        for device_line in arr_devices:
            device_fields: list[Any] = device_line.split("|")
            wifi_band = (
                device_fields[7] if len(device_fields) == FULL_FIELDS_NUM else ""
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

    async def get_sensor_data(self) -> dict[Any, Any]:
        """Load user_data page information."""
        _LOGGER.debug("Getting sensor data for host %s", self.host)

        reply_dict_1 = await self._get_sercomm_page("/data/user_data.json")
        reply_dict_2 = await self._get_sercomm_page("/data/statussupportstatus.json")
        reply_dict_3 = await self._get_sercomm_page("/data/statussupportrestart.json")

        return reply_dict_1 | reply_dict_2 | reply_dict_3 | self._overview

    async def get_docis_data(self) -> dict[Any, Any]:
        """Get docis data."""
        return {}

    async def get_voice_data(self) -> dict[Any, Any]:
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
            self.host,
        )
        payload = {f"{connection_type}_reconnect": "1"}
        try:
            if not await self._check_logged_in():
                await self.login()
            await self._post_sercomm_page("/data/statussupportrestart.json", payload)
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
        _LOGGER.debug("Restarting router %s", self.host)
        payload = {"restart_device": "1"}
        try:
            if not await self._check_logged_in():
                await self.login()
            await self._post_sercomm_page("/data/statussupportrestart.json", payload, 2)
        except asyncio.exceptions.TimeoutError:
            pass

    async def ping(
        self,
        ip_address: str,
        count: int = 1,
        ping_size: int = 56,
        ping_interval: int = 1000,
        retries: int = 15,
    ) -> dict:
        """Ping."""
        raise NotImplementedError("Not implemented yet.")

    async def traceroute(
        self,
        ip_address: str,
        count: int = 30,
        ip_type: str = "Ipv4",
        retries: int = 15,
    ) -> dict:
        """Traceroute."""
        raise NotImplementedError("Not implemented yet.")

    async def dns_resolve(
        self,
        hostname: str,
        dns_server: str = "1.1.1.1",
        record_type: str = "A",
        retries: int = 15,
    ) -> dict:
        """DNS Test."""
        raise NotImplementedError("Not implemented yet.")
