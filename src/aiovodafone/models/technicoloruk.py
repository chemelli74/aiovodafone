"""Vodafone UK Technicolor device API implementation."""

from collections.abc import Iterator
from datetime import datetime
from http import HTTPMethod
from typing import TYPE_CHECKING, Any

import dateparser

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import _LOGGER
from aiovodafone.exceptions import GenericLoginError
from aiovodafone.models.srp import calculate_session_key, generate_client_public

if TYPE_CHECKING:
    from aiohttp import ClientResponse
    from yarl import URL


class VodafoneStationTechnicolorUkApi(VodafoneStationCommonApi):
    """Vodafone UK Technicolor device API implementation."""

    async def _get_csrf_token(self) -> str:
        _LOGGER.debug("Fetching CSRF token")
        reply: ClientResponse = await self._request_url_result(
            HTTPMethod.GET,
            self.base_url.joinpath("login.lp").with_query(action="getcsrf"),
        )
        return await reply.text()

    async def login(self, force_logout: bool = False) -> bool:
        """Log into the router afresh."""
        _LOGGER.debug("Logging into %s (force: %s)", self.base_url.host, force_logout)

        if force_logout:
            _LOGGER.warning("Cannot forcibly log others out with this kind of router.")

        csrf_token: str = await self._get_csrf_token()
        _LOGGER.debug(csrf_token)

        auth_url = self.base_url.joinpath("authenticate")

        # Generate client public key
        f_private, d_public = generate_client_public()
        d_hex = f"{d_public:x}"

        auth1_reply: ClientResponse = await self._request_url_result(
            HTTPMethod.POST,
            auth_url,
            payload={"CSRFtoken": csrf_token, "I": "vodafone", "A": d_hex},
        )
        _LOGGER.debug(msg=await auth1_reply.text())
        auth1_response = await auth1_reply.json()
        salt = auth1_response.get("s")
        server_public = auth1_response.get("B")

        if not salt or not server_public:
            msg = "Invalid response from first authentication request"
            raise GenericLoginError(msg)

        client_proof, verification, _ = calculate_session_key(
            f_private,
            d_public,
            salt,
            server_public,
            # self.username,
            self.password,
        )

        auth2_reply: ClientResponse = await self._request_url_result(
            HTTPMethod.POST,
            auth_url,
            payload={"CSRFtoken": csrf_token, "M": client_proof},
        )
        _LOGGER.debug(msg=await auth2_reply.text())

        auth2_response = await auth2_reply.json()
        server_proof = auth2_response.get("M")

        if not server_proof:
            msg = "Invalid response from second authentication request"
            raise GenericLoginError(msg)

        if verification.upper() != server_proof.upper():
            msg = "Server authentication failed - proof mismatch"
            raise GenericLoginError(msg)

        _LOGGER.info(auth2_reply.cookies)

        return True

    @staticmethod
    def _parse_device(data: dict[str, Any]) -> VodafoneStationDevice | None:
        # Needs a MAC address to uniquely identify device
        mac_address = data.get("MACAddress")
        if not mac_address:
            return None

        return VodafoneStationDevice(
            mac=mac_address,
            connected=data.get("State") == "1",
            connection_type=(
                {
                    "wireless": "WiFi",
                    "ethernet": "Ethernet",
                }.get(data.get("InterfaceType", ""), "")
            ),
            ip_address=data.get("IPv4", ""),
            name=data.get("HostName", ""),
            type=(data.get("X_VODAFONE_Fingerprint.Class") or data.get("Class", "")),
            wifi=data.get("Radio", ""),
        )

    @staticmethod
    def _iterate_devices(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
        yield from data.get("ethList", [])
        for bridge in data.get("wifiList", {}).values():
            if not isinstance(bridge, dict):
                continue
            for band in bridge.values():
                if not isinstance(band, dict):
                    continue
                yield from band.get("devices", [])

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Retrieve information about all devices on the network."""
        url: URL = self.base_url.joinpath("modals/overview.lp").with_query(
            {"status": "WifiInfo", "auto_update": "true"}
        )
        reply = await self._request_url_result(HTTPMethod.GET, url)
        devices: Iterator[VodafoneStationDevice | None] = map(
            self._parse_device, self._iterate_devices(await reply.json())
        )
        return {device.mac: device for device in devices if device is not None}

    async def get_sensor_data(self) -> dict[str, str]:
        """Fetch router system information."""
        sysinfo_reply = await self._request_url_result(
            HTTPMethod.GET,
            self.base_url.joinpath("modals/status-support/status.lp").with_query(
                {"status": "systemInfo"}
            ),
        )
        sysinfo: dict[str, Any] = (await sysinfo_reply.json()).get("systemParams", {})
        interfaces_reply = await self._request_url_result(
            HTTPMethod.GET,
            self.base_url.joinpath("modals/status-support/restart.lp").with_query(
                {"getInterfaceValues": "true"}
            ),
        )
        interfaces_info: dict[str, str] = await interfaces_reply.json()
        return {
            "sys_serial_number": sysinfo.get("sys_gw_serial", ""),
            "sys_firmware_version": sysinfo.get("sys_gw_version", ""),
            "sys_hardware_version": sysinfo.get("sys_hw_version", ""),
            "sys_uptime": sysinfo.get("sys_uptime", ""),
            "wan_status": interfaces_info.get("ethstatus", "down").lower(),
            "cm_status": interfaces_info.get("dslstatus", "down").lower(),
            "lan_mode": "",
        }

    async def get_docis_data(self) -> dict[str, Any]:
        """Stub method, no data returned."""
        return {}

    async def get_voice_data(self) -> dict[str, Any]:
        """Stub method, no data returned."""
        return {}

    async def restart_connection(self, connection_type: str) -> None:
        """Reconnect your DSL or Fibre connection."""
        if connection_type not in {"dsl", "ethwan"}:
            msg: str = f"Unknown connection type '{connection_type}'"
            raise ValueError(msg)
        await self._request_url_result(
            HTTPMethod.POST,
            self.base_url.joinpath("modals/status-support/restart.lp"),
            payload={
                f"reset_{connection_type}": 1,
                "CSRFtoken": await self._get_csrf_token(),
            },
        )
        raise NotImplementedError

    async def restart_router(self) -> None:
        """Perform router restart."""
        await self._request_url_result(
            HTTPMethod.POST,
            self.base_url.joinpath("modals/status-support/restart.lp"),
            payload={
                "system_reboot": "GUI",
                "CSRFtoken": await self._get_csrf_token(),
            },
        )

    async def logout(self) -> None:
        """Log out the current router session."""
        await self._request_url_result(
            HTTPMethod.POST,
            self.base_url.joinpath("home.lp"),
            payload={"action": "logout", "CSRFtoken": await self._get_csrf_token()},
        )

    def convert_uptime(self, uptime: str) -> datetime:
        """Parse human-readable uptime string to exact boot time.

        Accepts strings like '24 days, 15 hours, 1 minute and 41 seconds'
        """
        parsed_datetime = dateparser.parse(f"{uptime} ago")
        if parsed_datetime is None:
            msg = "Failed to parse uptime string"
            raise ValueError(msg)
        return parsed_datetime
