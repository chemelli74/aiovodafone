"""Support for Vodafone Station."""
import asyncio
import hashlib
import hmac
import re
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from typing import Any

import aiohttp
from bs4 import BeautifulSoup, Tag

from .const import _LOGGER, HEADERS, LOGIN, USER_ALREADY_LOGGED_IN, DeviceType
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    ModelNotSupported,
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
        host: str, session: aiohttp.ClientSession
    ) -> DeviceType | None:
        """Finds out the device type of a Vodafone Stations and returns it as enum.
        The Technicolor devices always answer with a valid HTTP response, the
        Sercomm returns 404 on a missing page. This helps to determine which we are
        talking with.
        For detecting the Sercomm devices, a look up for a CSRF token is used.

        Args:
            host (str): The router's address, e.g. `192.168.1.1`
            session (aiohttp.ClientSession): the client session to issue HTTP request with

        Returns:
            DeviceType: If the device is a Technicolor, it returns
            `DeviceType.TECHNICOLOR`. If the device is a Sercomm, it returns `DeviceType.SERCOMM`.
            If neither of the device types match, it returns `None`.
        """
        async with session.get(
            f"http://{host}/api/v1/login_conf", headers=HEADERS
        ) as response:
            if response.status == 200:
                response_json = await response.json()
                if "data" in response_json and "ModelName" in response_json["data"]:
                    return DeviceType.TECHNICOLOR
        async with session.get(
            f"http://{host}/login.html", headers=HEADERS, ssl=False
        ) as response:
            if response.status == 200:
                # To identify the Sercomm devices before the login
                # There's no other sure way to identify a Sercomm device without login
                if "var csrf_token = " in await response.text():
                    return DeviceType.SERCOMM
        return None

    def __init__(self, host: str, username: str, password: str) -> None:
        """Initialize the scanner."""
        self.host = host
        self.protocol = "http"
        self.username = username
        self.password = password
        self.base_url = self._base_url()
        self.headers = HEADERS
        self.session: aiohttp.ClientSession
        self.csrf_token: str = ""
        self.encryption_key: str = ""
        self._unique_id: str | None = None
        self._overview: dict[str, Any] = {}
        self._devices: dict[str, VodafoneStationDevice] = {}

    def _client_session(self) -> None:
        """Create aiohttp ClientSession"""

        if not hasattr(self, "session") or self.session.closed:
            _LOGGER.debug("Creating HTTP ClientSession")
            jar = aiohttp.CookieJar(unsafe=True)
            self.session = aiohttp.ClientSession(cookie_jar=jar)

    def _base_url(self) -> str:
        """Create base URL"""
        return f"{self.protocol}://{self.host}"

    async def _set_cookie(self) -> None:
        """Enable required session cookie."""
        self.session.cookie_jar.update_cookies(
            SimpleCookie(f"domain={self.host}; name=login_uid; value=1;")
        )

    async def _post_page_result(
        self, page: str, payload: dict[str, Any], timeout: int = 10
    ) -> aiohttp.ClientResponse:
        """Get data from a web page via POST."""
        _LOGGER.debug("POST page  %s from host %s", page, self.host)
        timestamp = int(datetime.now().timestamp())
        url = f"{self.base_url}{page}?_={timestamp}&csrf_token={self.csrf_token}"
        return await self.session.post(
            url,
            data=payload,
            headers=self.headers,
            timeout=timeout,
            ssl=False,
            allow_redirects=True,
        )

    async def _get_page_result(self, page: str) -> aiohttp.ClientResponse:
        """Get data from a web page via GET."""
        _LOGGER.debug("GET page  %s [%s]", page, self.host)
        timestamp = int(datetime.now().timestamp())
        url = f"{self.base_url}{page}?_={timestamp}&csrf_token={self.csrf_token}"

        return await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=False,
        )

    @abstractmethod
    def convert_uptime(self, uptime: str) -> datetime:
        pass

    async def close(self) -> None:
        """Router close session."""
        if hasattr(self, "session"):
            await self.session.close()

    @abstractmethod
    async def login(self) -> bool:
        pass

    @abstractmethod
    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        pass

    @abstractmethod
    async def get_sensor_data(self) -> dict[Any, Any]:
        pass

    @abstractmethod
    async def logout(self) -> None:
        pass


class VodafoneStationTechnicolorApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Technicolor firmware."""

    async def _encrypt_string(
        self, credential: str, salt: str, salt_web_ui: str
    ) -> str:
        """Calculates login hash from the password, the salt and the salt from the web UI.

        Args:
            credential (str): login password for the user
            salt (str): salt given by the login response
            salt_web_ui (str): salt given by the web UI

        Returns:
            str: the hash for the session API
        """
        _LOGGER.debug("Calculate credential hash")
        a = hashlib.pbkdf2_hmac(
            "sha256",
            bytes(credential, "utf-8"),
            bytes(salt, "utf-8"),
            1000,
        ).hex()[:32]
        b = hashlib.pbkdf2_hmac(
            "sha256",
            bytes(a, "utf-8"),
            bytes(salt_web_ui, "utf-8"),
            1000,
        ).hex()[:32]
        return b

    async def login(self) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.host)
        self._client_session()

        _LOGGER.debug("Get salt for login")
        payload = {"username": self.username, "password": "seeksalthash"}
        salt_response = await self._post_page_result(
            page="/api/v1/session/login", payload=payload
        )

        salt_json = await salt_response.json()

        salt = salt_json["salt"]
        salt_web_ui = salt_json["saltwebui"]

        # Calculate credential hash
        password_hash = await self._encrypt_string(self.password, salt, salt_web_ui)

        # Perform login
        _LOGGER.debug("Perform login")
        login_response = await self._post_page_result(
            page="/api/v1/session/login",
            payload={"username": self.username, "password": password_hash},
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
        """
        Get all connected devices as a map of MAC address and device object

        Returns:
            dict[str, VodafoneStationDevice]: MAC address maps to VodafoneStationDevice
        """
        _LOGGER.debug("Get hosts")
        host_response = await self._get_page_result("/api/v1/host/hostTbl")
        host_json = await host_response.json()

        devices_dict = {}
        for device in host_json["data"]["hostTbl"]:
            connected = device["active"] == "true"
            connection_type = (
                "WiFi" if "WiFi" in device["layer1interface"] else "Ethernet"
            )
            ip_address = device["ipaddress"]
            name = device["hostname"]
            mac = device["physaddress"]
            type = device["type"]
            wifi = ""  # Technicolor Vodafone Station does not report wifi band

            vdf_device = VodafoneStationDevice(
                connected=connected,
                connection_type=connection_type,
                ip_address=ip_address,
                name=name,
                mac=mac,
                type=type,
                wifi=wifi,
            )
            devices_dict[mac] = vdf_device

        return devices_dict

    async def get_sensor_data(self) -> dict[Any, Any]:
        status_response = await self._get_page_result("/api/v1/sta_status")
        status_json = await status_response.json()
        _LOGGER.debug("GET reply (%s)", status_json)

        data = {}
        data["sys_serial_number"] = status_json["data"]["serialnumber"]
        data["sys_firmware_version"] = status_json["data"]["firmwareversion"]
        data["sys_hardware_version"] = status_json["data"]["hardwaretype"]
        data["sys_uptime"] = status_json["data"]["uptime"]
        return data

    def convert_uptime(self, uptime: str) -> datetime:
        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(
            seconds=int(uptime)
        )

    async def logout(self) -> None:
        # Logout
        _LOGGER.debug("Logout")
        await self._post_page_result("/api/v1/session/logout", payload={})


class VodafoneStationSercommApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Sercomm firmware."""

    async def _list_2_dict(self, data: dict[Any, Any]) -> dict[Any, Any]:
        """Transform list in a dict"""

        kv_tuples = [(list(v.keys())[0], (list(v.values())[0])) for v in data]
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
        self, page: str, payload: dict[str, Any], timeout: int = 10
    ) -> dict[Any, Any]:
        """Post html page and process reply."""

        reply = await self._post_page_result(page, payload, timeout)
        _LOGGER.debug("POST raw reply (%s): %s", page, await reply.text())
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("POST json reply (%s): %s", page, reply_json)
        return reply_json

    async def _check_logged_in(self) -> bool:
        """Check if logged in or not."""
        reply = await self._post_sercomm_page(
            "/data/login.json", {"loginUserChkLoginTimeout": self.username}
        )
        index = int(str(reply)) if reply else 0
        _LOGGER.debug("Login status: %s[%s]", LOGIN[index], reply)
        return bool(reply)

    async def _find_login_url(self) -> str:
        """
        Find the login page

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
        if reply.status in [403, 404]:
            raise ModelNotSupported
        reply_text = await reply.text()
        soup = BeautifulSoup(reply_text, "html.parser")
        meta_refresh = soup.find("meta", {"http-equiv": "Refresh"})
        if isinstance(meta_refresh, Tag) and "content" in meta_refresh.attrs.keys():
            meta_content = meta_refresh.get("content")
            parsed_qs = urllib.parse.parse_qs(str(meta_content), separator="; ")
            reply_url: str = parsed_qs["URL"][0]
            redirect_url = urllib.parse.urlparse(reply_url)
            if redirect_url.scheme != self.protocol:
                self.protocol = redirect_url.scheme
                self.base_url = self._base_url()
                _LOGGER.debug("Redirected login!")
                reply_text = await self._find_login_url()

        return reply_text

    async def _get_csrf_token(self, reply_text: str) -> None:
        """Load login page to get csrf token."""

        soup = BeautifulSoup(reply_text, "html.parser")
        script_tag = soup.find("script", string=True)
        try:
            token = re.findall("(?<=csrf_token)|[^']+", str(script_tag))[1]
        except IndexError:
            raise ModelNotSupported
        if not token:
            return None
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

    async def _reset(self) -> bool:
        """Reset page content before loading."""

        payload = {"chk_sys_busy": ""}
        reply = await self._post_page_result("/data/reset.json", payload)
        if isinstance(reply, aiohttp.ClientResponse):
            return reply.status == 200

        return False

    async def _login_json(self, username: str, password: str, useChallenge: bool = False) -> bool:
        """Login via json page"""

        if useChallenge:
            return_dict = await self._get_sercomm_page("/data/login.json")
            challenge = return_dict["challenge"]
            _LOGGER.debug("challenge: <%s>", challenge)
            payload = {
                "LoginName": username,
                "LoginPWD": hashlib.sha256(bytes(password + challenge, "utf-8")).hexdigest(),
                "challenge": challenge,
            }
        else:
            payload = {
                "LoginName": username,
                "LoginPWD": password,
            }

        reply_json = await self._post_sercomm_page("/data/login.json", payload)
        reply_int = int(str(reply_json))
        _LOGGER.debug("Login result: %s[%s]", LOGIN[reply_int], reply_json)

        if reply_int == 1:
            return True

        if reply_int == 2:
            raise AlreadyLogged

        if reply_int in [3, 4, 5]:
            raise CannotAuthenticate

        raise GenericLoginError

    async def get_sensor_data(self) -> dict[Any, Any]:
        """Load user_data page information."""
        _LOGGER.debug("Getting sensor data for host %s", self.host)

        reply_dict_1 = await self._get_sercomm_page("/data/user_data.json")
        reply_dict_2 = await self._get_sercomm_page("/data/statussupportstatus.json")
        reply_dict_3 = await self._get_sercomm_page("/data/statussupportrestart.json")

        return reply_dict_1 | reply_dict_2 | reply_dict_3 | self._overview

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

        # 'on|smartphone|Telefono Nora (2.4GHz)|00:0a:f5:6d:8b:38|192.168.1.128||2.4G;'
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
            wifi_band = device_fields[7] if len(device_fields) == 8 else ""
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

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert router uptime to last boot datetime."""
        d = int(uptime.split(":")[0])
        h = int(uptime.split(":")[1])
        m = int(uptime.split(":")[2])

        return datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(
            days=d, hours=h, minutes=m
        )

    async def login(self) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.host)
        try:
            self._client_session()
            html_page = await self._find_login_url()
        except (asyncio.exceptions.TimeoutError, aiohttp.ClientConnectorError) as exc:
            _LOGGER.warning("Connection error for %s", self.host)
            raise CannotConnect from exc

        await self._get_csrf_token(html_page)
        await self._get_user_lang()
        await self._set_cookie()
        await self._reset()

        if not self.encryption_key:
            _LOGGER.debug("Login: username[plain], password[challenge encrypted]")
            logged = await self._login_json(self.username, self.password, True)
        else:
            # First  try with both  username and password encrypted
            # Second try with plain username and password encrypted
            try:
                _LOGGER.debug("Login first try: username[encrypted], password[encrypted]")
                logged = await self._login_json(
                    await self._encrypt_string(self.username),
                    await self._encrypt_string(self.password),
                )
            except CannotAuthenticate:
                _LOGGER.debug("Login second try: username[plain], password[encrypted]")
                logged = await self._login_json(
                    self.username, await self._encrypt_string(self.password)
                )

        return logged

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
        except aiohttp.ClientResponseError as ex:
            _LOGGER.debug(
                'Client response error for "restart_connection" is: %s', ex.message
            )
            # Some models dump a text reply with wrong HTML headers as reply to a reconnection request
            if not ex.message.startswith("Invalid header token"):
                raise ex
            pass

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

    async def logout(self) -> None:
        """Router logout."""
        if hasattr(self, "session"):
            self.session.cookie_jar.clear()
