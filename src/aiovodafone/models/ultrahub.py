"""UltraHub Vodafone Station model API implementation."""

import base64
import contextlib
from datetime import UTC, datetime, timedelta
from http import HTTPMethod
from typing import Any, cast

import orjson
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

        returned_keys = await self.obtain_hub_keys()

        value_dict = SJCL().encrypt(
            self.password.encode("utf-8"),
            returned_keys["passphrase"],
            mode="ccm",
            count=1000,
            dk_len=16,
            salt=returned_keys["salt"],
        )
        # should not send back part of a key supplied by the hub
        value_dict.pop("salt")

        password = build_json_from_sjcl(value_dict)
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
            self.session.cookie_jar.update_cookies(response.cookies)

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
        data: dict[str, Any] = {WIFI_DATA: {}}

        retuned_keys = await self.obtain_hub_keys()

        ssids_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            "api/wifi/ssids/list.jst",
            params={"X_INTERNAL_FIELDS": "__id,Enable,SSID"},
        )

        keypass_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            "api/wifi/aps/list.jst",
            params={"__id_list": "3", "X_INTERNAL_FIELDS": "Security_KeyPassphrase"},
        )

        data[WIFI_DATA]["main"] = {
            "ssid": ssids_json["ssids"][0]["SSID"],
            "on": 1 if ssids_json["ssids"][0]["Enable"] == "true" else 0,
        }

        data[WIFI_DATA]["guest"] = {
            "ssid": ssids_json["ssids"][2]["SSID"],
            "on": 1 if ssids_json["ssids"][2]["Enable"] == "true" else 0,
        }

        json = orjson.loads(keypass_json["aps"][0]["Security_KeyPassphrase"])

        sjcl = SJCL()
        sjcl.salt_size = len(retuned_keys["salt"])
        json["salt"] = base64.b64encode(retuned_keys["salt"])
        json["iter"] = 1000

        pwd = sjcl.decrypt(json, retuned_keys["passphrase"]).decode("utf-8")

        data[WIFI_DATA]["guest"]["qr_code"] = await self._generate_guest_qr_code(
            data[WIFI_DATA]["guest"]["ssid"], pwd, "WPA2+WPA3"
        )

        return data

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
        _LOGGER.debug("Set wifi status for %s", band)

        if (
            hasattr(self, "session")
            and self.csrf_token != ""
            and wifi_type == WifiType.GUEST
        ):
            body = {"ssids": {"3": {"Enable": "true" if enable else "false"}}}

            bodt_str = build_json_from_sjcl(body)

            payload = {"body": bodt_str, "csrf_token": self.csrf_token}

            with contextlib.suppress(GenericResponseError):
                await self._auto_hub_request_page_result(
                    HTTPMethod.POST, "api/wifi/bulk/update.jst", payload=payload
                )

    async def obtain_hub_keys(
        self,
    ) -> dict[str, Any]:
        """Before doing an encyript or decryipt you need to get a key."""
        reply_json = await self._auto_hub_request_page_result(
            HTTPMethod.GET,
            "api/users/details.jst",
            params={"__id": self.id, "X_INTERNAL_FIELDS": "X_VODAFONE_WebUISecret"},
        )

        if "X_VODAFONE_WebUISecret" in reply_json:
            web_secret = reply_json["X_VODAFONE_WebUISecret"]

            return {
                "passphrase": web_secret[:10],
                "salt": bytes(web_secret[10:], "utf-8"),
            }

        raise GenericLoginError("Failed to get hub keys.")
