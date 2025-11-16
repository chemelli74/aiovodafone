"""Vodafone UK Technicolor device API implementation."""

import asyncio
from collections.abc import Iterator
from datetime import datetime
from http import HTTPMethod
from typing import TYPE_CHECKING, Any

import dateparser

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import _LOGGER
from aiovodafone.exceptions import GenericLoginError
from aiovodafone.util.technicolor_srp import TechnicolorSRP

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
        srp = TechnicolorSRP(self.username, self.password)

        auth1_reply: ClientResponse = await self._request_url_result(
            HTTPMethod.POST,
            auth_url,
            payload={
                "CSRFtoken": csrf_token,
                "I": self.username,
                "A": srp.client_public_key_hex,
            },
        )
        _LOGGER.debug(msg=await auth1_reply.text())
        auth1_response = await auth1_reply.json()
        salt = auth1_response.get("s")
        server_public = auth1_response.get("B")

        if not salt or not server_public:
            msg = "Invalid response from first authentication request"
            raise GenericLoginError(msg)

        auth2_reply: ClientResponse = await self._request_url_result(
            HTTPMethod.POST,
            auth_url,
            payload={
                "CSRFtoken": csrf_token,
                "M": srp.calculate_proofs(salt, server_public),
            },
        )
        _LOGGER.debug(msg=await auth2_reply.text())

        auth2_response = await auth2_reply.json()
        server_proof = auth2_response.get("M")

        if not server_proof:
            msg = "Invalid response from second authentication request"
            raise GenericLoginError(msg)

        if not srp.verify_server(server_proof):
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
            ip_address=data.get("IPv4") or data.get("DhcpLeaseIP") or "",
            name=data.get("HostName") or data.get("FriendlyName") or "",
            type=(
                data.get("X_VODAFONE_Fingerprint.Class")
                or data.get("X_VF_ADTI.Class")
                or data.get("Class")
                or ""
            ),
            wifi=data.get("Radio") or data.get("radio") or "",
        )

    @staticmethod
    def _iterate_devices(data: dict[str, Any]) -> Iterator[dict[str, Any]]:
        # Ethernet-connected devices
        yield from data.get("ethList", [])

        # Devices returning a separate list for each WiFi band
        yield from data.get("wifiList24", [])
        yield from data.get("wifiList5", [])
        yield from data.get("guestWifi24", [])
        yield from data.get("guestWifi5", [])

        # Devices returning a more complex nested dictionary
        # I presume this was changed with the addition of 6GHz
        for bridge in data.get("wifiList", {}).values():
            if not isinstance(bridge, dict):
                # skip over wifiActiveCount=N field
                continue
            for band in bridge.values():
                if not isinstance(band, dict):
                    # skip over wifiActiveCount=N field
                    continue
                yield from band.get("devices", [])

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Retrieve information about all devices on the network."""
        endpoint: URL = self.base_url.joinpath("modals/overview.lp")

        # Newer models (tested on v22 firmware) return both WiFi and ethernet
        # device information from status=WifiInfo despite the name
        reply = await self._request_url_result(
            HTTPMethod.GET, endpoint.with_query({"status": "WifiInfo"})
        )
        if reply.content_type == "application/json":
            data = await reply.json()
        else:
            # Older models (tested on v19 firmware) use lowercase wifiInfo and require
            # a separate call to retrieve ethernet-connected devices.
            wifi_reply, eth_reply = await asyncio.gather(
                self._request_url_result(
                    HTTPMethod.GET, endpoint.with_query({"status": "wifiInfo"})
                ),
                self._request_url_result(
                    HTTPMethod.GET, endpoint.with_query({"status": "networkInfo"})
                ),
            )
            data = {**(await wifi_reply.json()), **(await eth_reply.json())}
        devices: Iterator[VodafoneStationDevice | None] = map(
            self._parse_device, self._iterate_devices(data)
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
        # strip sub-second accuracy, the uptime string is accurate to the second only
        return parsed_datetime.replace(microsecond=0)
