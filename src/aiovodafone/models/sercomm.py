"""Sercomm Vodafone Station model API implementation."""

import asyncio
import binascii
import hashlib
import hmac
import re
import urllib.parse
from datetime import UTC, datetime, timedelta
from http import HTTPMethod, HTTPStatus
from typing import Any, cast

import orjson
from aiohttp import (
    ClientConnectorError,
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from bs4 import BeautifulSoup
from yarl import URL

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    DEVICE_SERCOMM_LOGIN_STATUS,
    DEVICES_SETTINGS,
    POST_RESTART_TIMEOUT,
    WIFI_DATA,
    WifiBand,
    WifiType,
)
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    GenericResponseError,
)
from aiovodafone.sjcl import SJCL


class VodafoneStationSercommApi(VodafoneStationCommonApi):
    """Queries Vodafone Station running Sercomm firmware."""

    def __init__(
        self,
        url: URL,
        username: str,
        password: str,
        session: ClientSession,
    ) -> None:
        """Initialize Sercomm API."""
        super().__init__(url, username, password, session)
        self._wifi_plain_data: dict[str, str] = {}
        self._sjcl_iterations = 1000
        self._sjcl_dklen = 16

    async def _list_2_dict(self, data: list[dict[str, Any]]) -> dict[str, Any]:
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
        if isinstance(reply_json, dict):
            return reply_json
        return await self._list_2_dict(reply_json)

    async def _post_sercomm_page(
        self,
        page: str,
        payload: dict[str, Any] | str,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> dict[Any, Any] | str:
        """Post html page and process reply."""
        reply = await self._request_page_result(HTTPMethod.POST, page, payload, timeout)
        _LOGGER.debug("POST raw reply (%s): %s", page, await reply.text())
        reply_json = await reply.json(content_type="text/html")
        _LOGGER.debug("POST json reply (%s): %s", page, reply_json)
        return cast("dict[str, Any]", reply_json)

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
            raise GenericResponseError from err
        if not token:
            return
        self.csrf_token = token
        _LOGGER.debug("csrf_token obtained")

    async def _get_user_lang(self) -> None:
        """Load user_lang page to get."""
        return_dict = await self._get_sercomm_page("data/user_lang.json")
        self.encryption_key = return_dict["encryption_key"]
        self.salt = return_dict["salt"]
        _LOGGER.debug("encryption_key and salt obtained")

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
        _LOGGER.debug("challenge obtained")
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

    def _sjcl_derived_key(self) -> str:
        """Derive PBKDF2-HMAC-SHA256 key."""
        salt = bytes.fromhex(self.salt)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            self.password.encode("utf-8"),
            salt,
            self._sjcl_iterations,
            self._sjcl_dklen,
        )
        return binascii.hexlify(key).decode("utf-8")

    def _sjcl_decrypt(self, encrypted_data: dict[str, Any]) -> str:
        """Decrypt data using SJCL with PBKDF2-HMAC-SHA256 key derivation."""
        derived_key = self._sjcl_derived_key()
        return SJCL().decrypt(encrypted_data, derived_key).decode("utf-8")

    def _sjcl_encrypt(self, plain_data: str) -> dict[str, Any]:
        """Encrypt data using SJCL with PBKDF2-HMAC-SHA256 key derivation."""
        derived_key = self._sjcl_derived_key()
        return SJCL().encrypt(
            plain_data.encode("utf-8"),
            derived_key,
            mode="ccm",
            count=self._sjcl_iterations,
            dk_len=self._sjcl_dklen,
            iv_length=12,
        )

    def _build_payload_from_sjcl_json(self, encrypted_json: dict[str, Any]) -> str:
        """Build form payload to send to router."""
        # Convert bytes to strings if needed
        for k, v in encrypted_json.items():
            if isinstance(v, bytes):
                encrypted_json[k] = v.decode("utf-8")
        # Dump to raw JSON string (no URL encoding)
        return orjson.dumps(encrypted_json).decode("utf-8")

    async def _wifi_ssid_split_disabled(self, wifi_plain_data: dict[str, Any]) -> bool:
        """Check if Wi-Fi SSID split is disabled."""
        return (
            wifi_plain_data.get("split_ssid_enable")
            or wifi_plain_data.get("split_ssid")
        ) == "0"

    async def _format_sensor_wifi_data(
        self, encrypted_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Format WI-FI data as dict."""
        self._wifi_plain_data = wifi_plain_data = {
            k: v
            for d in orjson.loads(self._sjcl_decrypt(encrypted_data))
            for k, v in d.items()
        }

        _LOGGER.debug("Decrypted Wi-Fi data: %s", wifi_plain_data)

        wifi_data: dict[str, Any] = {WIFI_DATA: {}}

        for wifi in (WifiType.MAIN, WifiType.GUEST):
            for band in (WifiBand.BAND_2_4_GHZ, WifiBand.BAND_5_GHZ):
                if (
                    await self._wifi_ssid_split_disabled(self._wifi_plain_data)
                    and band is WifiBand.BAND_5_GHZ
                ):
                    # Skip unused 5 GHz entries when SSID split is disabled
                    continue
                frmt = await self._get_wifi_format(wifi, band)
                name = f"{wifi.name.lower()}{
                    '-5ghz' if band == WifiBand.BAND_5_GHZ else ''
                }"
                ssid = wifi_plain_data[f"wifi_ssid{frmt}"]

                entry = {
                    "on": int(wifi_plain_data[f"wifi_network_onoff{frmt}"]),
                    "ssid": ssid,
                }

                # Add QR code for guest Wi-Fi
                if wifi is WifiType.GUEST:
                    security = self._wifi_plain_data[f"wifi_protection{frmt}"]
                    pwd = self._wifi_plain_data[f"wifi_password{frmt}"]
                    entry["qr_code"] = await self._generate_guest_qr_code(
                        ssid, pwd, security
                    )

                wifi_data[WIFI_DATA][name] = entry

        return wifi_data

    async def _get_wifi_format(self, wifi_type: WifiType, band: WifiBand) -> str:
        """Get Wi-Fi dict key."""
        wifi = "" if wifi_type == WifiType.MAIN else "_guest"
        wifi_band = "" if band == WifiBand.BAND_2_4_GHZ else "_5g"

        return f"{wifi}{wifi_band}"

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert router uptime to last boot datetime."""
        d = int(uptime.split(":", maxsplit=1)[0])
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
                HTTPMethod.GET, DEVICES_SETTINGS["Sercomm"]["login_url"]
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
        arr_wifi_guest = ["Wifi (Guest)|" + dev for dev in arr_wifi_guest_filter]
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
                if len(device_fields) == DEVICES_SETTINGS["Sercomm"]["total_fields_num"]
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

    async def get_wifi_data(self) -> dict[str, Any]:
        """Get Wi-Fi data."""
        encrypted_data = await self._get_sercomm_page("data/wifi_general.json")
        return await self._format_sensor_wifi_data(encrypted_data)

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

    async def set_wifi_status(
        self,
        enable: bool,
        wifi_type: WifiType,
        band: WifiBand,
    ) -> None:
        """Enable/Disable Wi-Fi."""
        _LOGGER.debug(
            "Switching %s Wi-Fi (%s) to %s for router %s",
            wifi_type,
            band,
            enable,
            self.base_url.host,
        )
        wifi_plain_data = self._wifi_plain_data.copy()

        # Set the new status
        wifi_plain_data[
            f"wifi_network_onoff{await self._get_wifi_format(wifi_type, band)}"
        ] = str(int(enable))

        # Firmware bug:
        # when SSID split is disabled, API defaults to 'wifi_ssid_5g'
        # while Web UI implicitly mirrors 'wifi_ssid' to both bands.
        if await self._wifi_ssid_split_disabled(wifi_plain_data):
            wifi_plain_data["wifi_ssid_5g"] = wifi_plain_data["wifi_ssid"]

        # Build the data to encrypt as a string
        wifi_data = "&".join(
            f"{key}={
                urllib.parse.quote_plus(wifi_plain_data[key])
                if 'password' in key
                else wifi_plain_data[key]
            }"
            for key in wifi_plain_data
        )

        # Encrypt via sjcl.py
        encrypted_sjcl_json = self._sjcl_encrypt(wifi_data)

        # Build payload to send to router
        payload = self._build_payload_from_sjcl_json(encrypted_sjcl_json)
        _LOGGER.debug("Payload for set_wifi_status: %s", payload)

        # Refresh CSRF token
        reply = await self._request_page_result(
            HTTPMethod.GET, "wifi_page/general.html"
        )
        await self._get_csrf_token(await reply.text())

        # Send the request
        reply = await self._post_sercomm_page("data/wifi_general.json", payload)
        if str(reply) != "1":
            raise GenericResponseError(f"Unexpected set_wifi_status response: {reply}")
