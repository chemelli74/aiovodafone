"""UltraHub Vodafone Station model API implementation."""

import base64
import contextlib
import os
from datetime import UTC, datetime, timedelta
from http import HTTPMethod, HTTPStatus
from typing import Any, cast

import orjson
from aiohttp import (
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from yarl import URL

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    DEVICES_SETTINGS,
    WIFI_DATA,
    WifiBand,
    WifiType,
)
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    GenericLoginError,
    GenericResponseError,
)


class VodafoneStationUltraHubApi(VodafoneStationCommonApi):
    """Queries Vodafone Ultra Hub."""

    def __init__(
        self, url: URL, username: str, password: str, session: ClientSession
    ) -> None:
        """Initialize id as it may change in the future."""
        super().__init__(url, username, password, session)
        self.id = DEVICES_SETTINGS["UltraHub"]["default_id"]

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.base_url.host)

        if not force_logout:
            self.csrf_token = ""

        reply = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            DEVICES_SETTINGS["UltraHub"]["login_url"],
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
            "api/users/details.jst",
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

            if reply_json.get("X_INTERNAL_Password_Status") == "Invalid_PWD":
                await self._cleanup_session()
                raise CannotAuthenticate

            if reply_json.get("X_INTERNAL_Is_Duplicate") == "true":
                await self._cleanup_session()
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

        value_dict = {
            "iv": b64_iv,
            "v": 1,
            "iter": 1000,
            "ks": 128,
            "ts": 64,
            "mode": "ccm",
            "adata": "",
            "cipher": "aes",
            "ct": b64_ct,
        }
        return cast("str", orjson.dumps(value_dict).decode("utf-8"))

    def _truncate_iv(
        self,
        iv: bytes,
        ol: int,  # in bits (output length including tag)
        tlen: int,  # in bytes
    ) -> bytes:
        """Calculate the nonce as it can not be 16 bytes."""
        ivl = len(iv)  # iv length in bytes
        ol = (ol - tlen) // 8

        # "compute the length of the length" (see ccm.js)
        loop = 2
        max_length_field_bytes = 4  # Maximum L parameter per CCM spec
        while (loop < max_length_field_bytes) and (ol >> (8 * loop)) > 0:
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
        url = self.base_url.joinpath(page)
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
            if response.status != HTTPStatus.OK:
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
            if "csrf_token" in reply_json:
                self.csrf_token = reply_json["csrf_token"]

            return response

    async def _cleanup_session(self) -> None:
        """Cleanup session."""
        self.csrf_token = ""
        self.session.cookie_jar.clear()  # may be clear by domain

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert uptime to datetime."""
        return datetime.now(tz=UTC) - timedelta(
            seconds=int(uptime),
        )

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get router device data."""
        _LOGGER.debug("Get hosts")

        devices_dict: dict[str, VodafoneStationDevice] = {}

        reply = await self._auto_hub_request_page_result(
            HTTPMethod.GET, "api/device/bulk/details.jst"
        )

        reply_json = await reply.json()

        for device in reply_json.get("hosts", []):
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
            HTTPMethod.GET, "api/device/details.jst"
        )

        reply_json = await reply.json()

        data: dict[str, Any] = {}

        data["sys_firmware_version"] = reply_json["SoftwareVersion"]
        data["sys_hardware_version"] = reply_json["HardwareVersion"]
        data["sys_serial_number"] = reply_json["SerialNumber"]
        data["sys_uptime"] = reply_json["UpTime"]
        data["wan_status"] = ""
        data["cm_status"] = ""
        data["lan_mode"] = reply_json["X_VODAFONE_WANType"]

        for device in reply_json["INTERNAL_CPEInterface_List"]:
            if device["DisplayName"] == "WWAN":
                data["wan_status"] = device["Phy_Status"]
            if device["DisplayName"] == "WANoE":
                data["cm_status"] = device["Phy_Status"]

        return data

    async def get_wifi_data(
        self,
    ) -> dict[str, Any]:
        """Get Wi-Fi data."""
        _LOGGER.debug("Get Wi-Fi data not implemented for UltraHub devices")
        return {WIFI_DATA: {}}

    async def get_docis_data(self) -> dict[str, Any]:
        """Get router docis data."""
        return {}

    async def get_voice_data(self) -> dict[str, Any]:
        """Get router voice data."""
        return {}

    async def restart_connection(self, connection_type: str) -> None:
        """Internet Connection restart."""
        raise NotImplementedError("Method not implemented for UltraHub devices")

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)

        payload = {"RebootDevice": "true", "csrf_token": self.csrf_token}

        with contextlib.suppress(GenericResponseError):
            await self._auto_hub_request_page_result(
                HTTPMethod.POST, "api/device/update.jst", payload=payload
            )

        await self._cleanup_session()

    async def logout(self) -> None:
        """Router logout."""
        _LOGGER.debug("Log out of router %s", self.base_url.host)
        if hasattr(self, "session") and self.csrf_token != "":
            payload = {"__id": self.id, "csrf_token": self.csrf_token}

            with contextlib.suppress(GenericResponseError):
                await self._auto_hub_request_page_result(
                    HTTPMethod.POST, "api/users/logout.jst", payload=payload
                )

            await self._cleanup_session()

    async def set_wifi_status(
        self,
        enable: bool,
        wifi_type: WifiType,
        band: WifiBand,
    ) -> None:
        """Enable/Disable Wi-Fi."""
        raise NotImplementedError("Method not implemented for UltraHub devices")
