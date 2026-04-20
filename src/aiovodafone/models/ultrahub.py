"""UltraHub Vodafone Station model API implementation."""

import contextlib
import hashlib
from datetime import UTC, datetime, timedelta
from http import HTTPMethod
from typing import Any, cast

from aiohttp import (
    ClientSession,
)
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
from aiovodafone.sjcl import SJCL, build_json_from_sjcl


class VodafoneStationUltraHubApi(VodafoneStationCommonApi):
    """Queries Vodafone Ultra Hub."""

    def __init__(
        self, url: URL, username: str, password: str, session: ClientSession
    ) -> None:
        """Initialize id as it may change in the future."""
        super().__init__(url, username, password, session)
        self.id = DEVICES_SETTINGS["UltraHub"]["default_id"]
        self._sjcl_iterations = 1000
        self._sjcl_dklen = 16
        self.salt: str = ""
        self.salt_web_ui: str = ""

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s", self.base_url.host)

        if not force_logout:
            self.csrf_token = ""

        reply_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            DEVICES_SETTINGS["UltraHub"]["login_url"],
            params={"X_INTERNAL_FIELDS": "X_RDK_ONT_Veip_1_OperationalState"},
            set_cookie=True,
        )

        if "X_INTERNAL_ID" in reply_json:
            self.id = reply_json["X_INTERNAL_ID"]

        if self.csrf_token == "":
            raise CannotAuthenticate

        reply_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            "api/users/details.jst",
            params={"__id": self.id, "X_INTERNAL_FIELDS": "X_VODAFONE_WebUISecret"},
        )

        if "X_VODAFONE_WebUISecret" in reply_json:
            web_secret = reply_json["X_VODAFONE_WebUISecret"]
            self.salt_web_ui = web_secret[:10]
            self.salt = web_secret[10:]
            password = self._encrypt_string()

            payload = {
                "__id": self.id,
                "X_VODAFONE_Password": password,
                "Push": str(force_logout).lower(),
                "csrf_token": self.csrf_token,
            }

            reply_json = await self._auto_hub_request_page_result(
                HTTPMethod.POST,
                "api/users/login.jst",
                payload=payload,
                set_cookie=True,
            )

            if reply_json.get("X_INTERNAL_Password_Status") == "Invalid_PWD":
                await self._cleanup_session()
                raise CannotAuthenticate

            if reply_json.get("X_INTERNAL_Is_Duplicate") == "true":
                await self._cleanup_session()
                raise AlreadyLogged

            return True

        raise GenericLoginError

    def _sjcl_derived_key(self) -> bytes:
        """Derive PBKDF2-HMAC-SHA256 key."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            self.salt_web_ui.encode("utf-8"),
            bytes(self.salt, "utf-8"),
            self._sjcl_iterations,
            self._sjcl_dklen,
        )

    def _encrypt_string(self) -> str:
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

        key = self._sjcl_derived_key()

        value_dict = SJCL().encrypt(
            self.password.encode("utf-8"),
            key.hex(),
            mode="ccm",
            count=self._sjcl_iterations,
            dk_len=self._sjcl_dklen,
            salt=self.salt_web_ui.encode("utf-8"),
        )
        # salt is not needed as it is derived from the web secret
        value_dict.pop("salt")
        return build_json_from_sjcl(value_dict)

    async def _auto_hub_request_page_result(
        self,
        method: str,
        page: str,
        payload: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        set_cookie: bool = False,
    ) -> dict[str, Any]:
        """Request data from a web page."""
        url = self.base_url.joinpath(page)
        _LOGGER.debug("%s page %s", method, url)

        response = await self._request_page_result(
            method,
            page,
            payload=payload,
            timeout=DEFAULT_TIMEOUT,
            query=params if params is not None else {},
            allow_redirects=False,
        )

        reply_json = await response.json()

        if "csrf_token" in reply_json:
            self.csrf_token = reply_json["csrf_token"]

        if set_cookie:
            self.session.cookie_jar.update_cookies(response.cookies, self.base_url)

        return cast("dict[str, Any]", reply_json)

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

        reply_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET, "api/device/bulk/details.jst"
        )

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
        reply_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET, "api/device/details.jst"
        )

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

    async def restart_connection(
        self, connection_type: str
    ) -> None:  # pragma: no cover
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
    ) -> None:  # pragma: no cover
        """Enable/Disable Wi-Fi."""
        raise NotImplementedError("Method not implemented for UltraHub devices")
