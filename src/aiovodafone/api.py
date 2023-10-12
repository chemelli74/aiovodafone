"""Support for Vodafone Station."""
import asyncio
import hashlib
import hmac
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from typing import Any

import aiohttp
from bs4 import BeautifulSoup, Tag

from .const import _LOGGER, LOGIN
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
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


class VodafoneStationCommonApi:
    """Common API calls for Vodafone Station routers."""

    def __init__(self, host: str, username: str, password: str) -> None:
        """Initialize the scanner."""
        self.host = host
        self.protocol = "http"
        self.username = username
        self.password = password
        self.base_url = self._base_url()
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.5",
            "DNT": "1",
        }
        jar = aiohttp.CookieJar(unsafe=True)
        self.session = aiohttp.ClientSession(cookie_jar=jar)
        self.csrf_token: str = ""
        self.encryption_key: str = ""
        self._unique_id: str | None = None
        self._overview: dict[str, Any] = {}
        self._devices: dict[str, VodafoneStationDevice] = {}

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

    async def close(self) -> None:
        """Router close session."""
        await self.session.close()


class VodafoneStationTechnicolorApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Technicolor firmware."""


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
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("POST reply (%s): %s", page, reply_json)
        return reply_json

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

    async def _login_json(self, username: str, password: str) -> bool:
        """Login via json page"""

        payload = {
            "LoginName": username,
            "LoginPWD": password,
        }
        reply_json = await self._post_sercomm_page("/data/login.json", payload)
        _LOGGER.debug("Login result: %s[%s]", LOGIN[int(str(reply_json))], reply_json)

        if reply_json == "1":
            return True

        if reply_json == "2":
            raise AlreadyLogged

        if reply_json in ["3", "4", "5"]:
            raise CannotAuthenticate

        return False

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

    async def convert_uptime(self, uptime: str) -> datetime:
        """Convert router uptime to last boot datetime."""
        d = int(uptime.split(":")[0])
        h = int(uptime.split(":")[1])
        m = int(uptime.split(":")[2])

        return datetime.utcnow() - timedelta(days=d, hours=h, minutes=m)

    async def login(self) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.host)
        try:
            html_page = await self._find_login_url()
        except (asyncio.exceptions.TimeoutError, aiohttp.ClientConnectorError) as exc:
            _LOGGER.warning("Connection error for %s", self.host)
            raise CannotConnect from exc

        await self._get_csrf_token(html_page)
        await self._get_user_lang()
        await self._set_cookie()
        await self._reset()

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
            await self._post_sercomm_page("/data/statussupportrestart.json", payload)
        except aiohttp.ClientResponseError as ex:
            # Some models dump a text reply with wrong HTML headers as reply to a reconnection request
            if not ex.message.startswith("Invalid header token"):
                raise ex
            pass

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.host)
        payload = {"restart_device": "1"}
        try:
            await self._post_sercomm_page("/data/statussupportrestart.json", payload, 2)
        except asyncio.exceptions.TimeoutError:
            pass

    async def logout(self) -> None:
        """Router logout."""
        self.session.cookie_jar.clear()
