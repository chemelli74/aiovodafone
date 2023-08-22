"""Support for Vodafone Station."""
import asyncio
import hashlib
import hmac
import html
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime
from http.cookies import SimpleCookie
from typing import Any

import aiohttp
import bs4

from .const import _LOGGER, LOGIN
from .exceptions import AlreadyLogged, CannotAuthenticate, CannotConnect


@dataclass
class VodafoneStationDevice:
    """Vodafone Station device class."""

    connected: bool
    connection_type: str
    ip_address: str
    name: str
    mac: str
    wifi: str


class VodafoneStationApi:
    """Queries router running Vodafone Station firmware."""

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
        self._devices: dict[str, VodafoneStationDevice] = {}

    def _base_url(self) -> str:
        """Create base URL"""
        return f"{self.protocol}://{self.host}"

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
        reply_text = await reply.text()
        soup = bs4.BeautifulSoup(reply_text, "html.parser")
        meta_refresh = soup.find("meta", {"http-equiv": "Refresh"})
        if meta_refresh is not None:
            meta_content = meta_refresh["content"]
            reply_url = urllib.parse.parse_qs(meta_content, separator="; ")["URL"][0]
            redirect_url = urllib.parse.urlparse(reply_url)
            if redirect_url.scheme != self.protocol:
                self.protocol = redirect_url.scheme
                self.base_url = self._base_url()
                _LOGGER.debug("Redirected login!")
                reply_text = await self._find_login_url()

        return reply_text

    async def _get_csrf_token(self, reply_text: str) -> None:
        """Load login page to get csrf token."""

        soup = bs4.BeautifulSoup(reply_text, "html.parser")
        script_tag = soup.find("script", string=True)
        token = re.findall("(?<=csrf_token)|[^']+", script_tag.string)[1]
        if not token:
            return None
        self.csrf_token = token
        _LOGGER.debug("csrf_token: <%s>", self.csrf_token)

    async def _get_user_lang(self) -> None:
        """Load user_lang page to get."""

        timestamp = datetime.now().strftime("%s")
        url = f"{self.base_url}/data/user_lang.json?_={timestamp}&csrf_token={self.csrf_token}"
        reply = await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=False,
        )

        j = await reply.json(content_type="text/html")
        user_obj = {}
        for item in j:
            key = list(item.keys())[0]
            val = list(item.values())[0]
            user_obj[key] = val

        self.encryption_key = user_obj["encryption_key"]
        _LOGGER.debug("encryption_key: <%s>", self.encryption_key)

    async def _encrypt_string(self, credential: str) -> str:
        """Encrypt username or password for login."""

        credential = urllib.parse.quote(credential)
        credential = html.unescape(credential)
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

    async def _set_cookie(self) -> None:
        """Enable required session cookie."""
        self.session.cookie_jar.update_cookies(
            SimpleCookie(f"domain={self.host}; name=login_uid; value=1;")
        )

    async def _reset(self) -> bool:
        """Reset page content before loading."""

        payload = {"chk_sys_busy": ""}
        timestamp = datetime.now().strftime("%s")
        url = f"{self.base_url}/data/reset.json?_={timestamp}&csrf_token={self.csrf_token}"
        reply = await self.session.post(
            url,
            data=payload,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=False,
        )

        return reply.status == 200

    async def _overview(self) -> dict[Any, Any]:
        """Load overview page information."""
        _LOGGER.debug("Getting overview for host %s", self.host)
        timestamp = datetime.now().strftime("%s")
        url = f"{self.base_url}/data/overview.json?_={timestamp}&csrf_token={self.csrf_token}"

        reply = await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=True,
        )
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("Full Response (overview): %s", reply_json)
        return reply_json

    async def _login_json(self, username: str, password: str) -> bool:
        """Login via json page"""

        payload = {
            "LoginName": username,
            "LoginPWD": password,
        }
        timestamp = datetime.now().strftime("%s")
        url = f"{self.base_url}/data/login.json?_={timestamp}&csrf_token={self.csrf_token}"
        reply = await self.session.post(
            url,
            data=payload,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=True,
        )
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("Login result: %s[%s]", LOGIN[int(reply_json)], reply_json)

        if reply_json == "1":
            return True

        if reply_json == "2":
            raise AlreadyLogged

        if reply_json in ["3", "4"]:
            raise CannotAuthenticate

        return False

    async def get_user_data(self) -> dict[Any, Any]:
        """Load user_data page information."""
        _LOGGER.debug("Getting user_data for host %s", self.host)
        timestamp = datetime.now().strftime("%s")
        url = f"{self.base_url}/data/user_data.json?_={timestamp}&csrf_token={self.csrf_token}"

        reply = await self.session.get(
            url,
            headers=self.headers,
            timeout=10,
            ssl=False,
            allow_redirects=False,
        )
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("Full Response (user_data): %s", reply_json)
        return reply_json

    async def get_all_devices(self) -> dict[str, VodafoneStationDevice]:
        """Get all connected devices."""

        _LOGGER.debug("Getting all devices for host %s", self.host)
        data = await self._overview()
        kv_tuples = [(list(v.keys())[0], (list(v.values())[0])) for v in data]
        key_values = {}
        for entry in kv_tuples:
            key_values[entry[0]] = entry[1]

        _LOGGER.debug("Data retrieved (key_values): %s", key_values)
        if (
            "wifi_user" not in key_values
            and "wifi_guest" not in key_values
            and "ethernet" not in key_values
        ):
            _LOGGER.info("No device in response from %s", self.host)
            return self._devices

        # 'on|smartphone|Telefono Nora (2.4GHz)|00:0a:f5:6d:8b:38|192.168.1.128||2.4G;'
        arr_devices = []
        arr_wifi_user = key_values["wifi_user"].split(";")
        arr_wifi_user = filter(lambda x: x.strip() != "", arr_wifi_user)
        arr_wifi_user = ["Wifi (Main)|" + dev for dev in arr_wifi_user]
        arr_wifi_guest = key_values["wifi_guest"].split(";")
        arr_wifi_guest = filter(lambda x: x.strip() != "", arr_wifi_guest)
        arr_wifi_guest = ["[Wifi (Guest)|" + dev for dev in arr_wifi_guest]
        arr_devices.append(arr_wifi_user)
        arr_devices.append(arr_wifi_guest)
        arr_ethernet = key_values["ethernet"].split(";")
        arr_ethernet = filter(lambda x: x.strip() != "", arr_ethernet)
        arr_ethernet = ["Ethernet|on|" + dev + "|||" for dev in arr_ethernet]
        arr_devices.append(arr_ethernet)
        arr_devices = [item for sublist in arr_devices for item in sublist]
        _LOGGER.debug("Array of devices: %s", arr_devices)

        for device_line in arr_devices:
            device_fields = device_line.split("|")
            try:
                dev_info = VodafoneStationDevice(
                    connection_type=device_fields[0],
                    connected=device_fields[1] == "on",
                    name=device_fields[3],
                    mac=device_fields[4],
                    ip_address=device_fields[5],
                    wifi=device_fields[7],
                )
                self._devices[dev_info.mac] = dev_info
            except (KeyError, IndexError):
                _LOGGER.warning("Error processing line: %s", device_line)

        return self._devices

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
            logged = await self._login_json(
                await self._encrypt_string(self.username),
                await self._encrypt_string(self.password),
            )
        except CannotAuthenticate:
            logged = await self._login_json(
                self.username, await self._encrypt_string(self.password)
            )

        return logged

    async def logout(self) -> None:
        """Router logout."""
        self.session.cookie_jar.clear()

    async def close(self) -> None:
        """Router close session."""
        await self.session.close()
