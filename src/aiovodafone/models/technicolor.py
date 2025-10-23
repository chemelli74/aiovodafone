"""Technicolor Vodafone Station model API implementation."""

import asyncio
import hashlib
from datetime import UTC, datetime, timedelta
from http import HTTPMethod
from typing import Any

from aiohttp import ClientResponseError

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import _LOGGER, DEVICES_SETTINGS
from aiovodafone.exceptions import AlreadyLogged, CannotAuthenticate, ResultTimeoutError


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

    async def _get_csrf_token(self, force_update: bool = False) -> None:
        """Retrieve CSRF token."""
        if force_update:
            self.headers.pop("X-CSRF-Token", None)

        if "X-CSRF-Token" in self.headers:
            _LOGGER.debug("CSRF Token already set")
            return

        # Any existing URL will do the job here
        csrf_res = await self._request_page_result(
            HTTPMethod.GET, "api/v1/wifi/1/SSIDEnable"
        )
        csrf_json = await csrf_res.json()
        _LOGGER.debug("csrf call response: %s", csrf_json)

        if token := csrf_json.get("token"):
            _LOGGER.debug("CSRF Token: %s", token)
            self.headers["X-CSRF-Token"] = token
        else:
            _LOGGER.warning("Failed to retrieve CSRF token")

    async def _trigger_diagnostic_call(
        self,
        check_url: str,
        data_url: str,
        payload: dict[str, Any],
        key: str,
        retries: int = 15,
    ) -> dict[str, Any]:
        """Trigger a specific diagnostic request to the router."""
        await self._get_csrf_token(force_update=True)

        url = f"api/v1/sta_diagnostic_utility/{check_url}"
        await self._request_page_result(
            HTTPMethod.POST,
            url,
            payload,
        )

        url = f"api/v1/sta_diagnostic_utility/{data_url}"
        for attempt in range(retries):
            try:
                response = await self._request_page_result(HTTPMethod.GET, url)
                result: dict[str, Any] = await response.json()
                if result and result.get("data", {}).get(key) != "InProgress":
                    return result

                _LOGGER.debug(
                    "'%s' results not ready, retrying (%d/%d)...",
                    key,
                    attempt + 1,
                    retries,
                )
                # sleep for 2 seconds, just like the dashboard does
                await asyncio.sleep(2)
            except ClientResponseError:
                _LOGGER.exception("Failed to retrieve '%s' results", key)

        raise ResultTimeoutError(
            f"'{key}' results not available after {retries} retries"
        )

    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""
        _LOGGER.debug("Logging into %s (force: %s)", self.base_url.host, force_logout)

        _LOGGER.debug("Get salt for login")
        payload = {"username": self.username, "password": "seeksalthash"}
        salt_response = await self._request_page_result(
            HTTPMethod.POST,
            page="api/v1/session/login",
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
        login_response = await self._request_page_result(
            HTTPMethod.POST,
            page="api/v1/session/login",
            payload=payload,
        )
        login_json = await login_response.json()
        if "error" in login_json and login_json["error"] == "error":
            if (
                login_json["message"]
                == DEVICES_SETTINGS["Technicolor"]["user_already_logged_in"]
            ):
                raise AlreadyLogged
            _LOGGER.error(login_json)
            raise CannotAuthenticate

        # Request menu otherwise the next call fails
        _LOGGER.debug("Get menu")
        await self._request_page_result(HTTPMethod.GET, "api/v1/session/menu")

        return True

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get all connected devices as a map of MAC address and device object.

        Returns
        -------
            dict[str, VodafoneStationDevice]: MAC address maps to VodafoneStationDevice

        """
        _LOGGER.debug("Get hosts")
        host_response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/host/hostTbl"
        )
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

    async def get_sensor_data(self) -> dict[str, Any]:
        """Get all sensors data."""
        _LOGGER.debug("Get sensors")
        status_response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_status"
        )
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

    async def get_docis_data(self) -> dict[str, Any]:
        """Get docis data."""
        _LOGGER.debug("Get docis data")
        response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_docsis_status"
        )
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

    async def get_voice_data(self) -> dict[str, Any]:
        """Get voice data."""
        _LOGGER.debug("Get voice data")
        response = await self._request_page_result(
            HTTPMethod.GET, "api/v1/sta_voice_status"
        )
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

    async def restart_connection(self, connection_type: str) -> None:  # noqa: ARG002
        """Internet Connection restart."""
        msg = f"Method not implemented for Technicolor device {self.base_url.host}"
        _LOGGER.error(msg)
        raise NotImplementedError(msg)

    async def restart_router(self) -> None:
        """Router restart."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)
        # NOTE This payload is identical to the request sent by the UI.
        payload = {
            "restart": "Router,Wifi,VoIP,Dect,MoCA",
            "ui_access": "reboot_device",
        }

        await self._request_page_result(HTTPMethod.POST, "api/v1/sta_restart", payload)

    async def logout(self) -> None:
        """Router logout."""
        _LOGGER.debug("Logout")
        await self._request_page_result(
            HTTPMethod.POST, "api/v1/session/logout", payload={}
        )

    async def ping(
        self,
        ip_address: str,
        count: int = 1,
        ping_size: int = 56,
        ping_interval: int = 1000,
        retries: int = 15,
    ) -> dict[str, Any]:
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
            dict: The ping results.

        """
        check_url = "ping"
        data_url = "ping_res"
        key = "ping_result"
        payload = {
            "ipaddress": ip_address,
            "count": count,
            "pingsize": ping_size,
            "pingintervalin": ping_interval,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )

    async def traceroute(
        self,
        ip_address: str,
        count: int = 30,
        ip_type: str = "Ipv4",
        retries: int = 15,
    ) -> dict[str, Any]:
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
        check_url = "traceroute"
        data_url = "traceroute_res"
        key = "traceroute_result"
        payload = {
            "traceroute_ip": ip_address,
            "count_tr": str(count),
            "ipaddresstype": ip_type,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )

    async def dns_resolve(
        self,
        hostname: str,
        dns_server: str = "1.1.1.1",
        record_type: str = "A",
        retries: int = 15,
    ) -> dict[str, Any]:
        """Trigger a DNS resolve diagnostic request to the router.

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
        check_url = "tracedns"
        data_url = "traceDns_res"
        # The result field is named "traceroute_result"
        # this is not a typo
        key = "traceroute_result"
        payload = {
            "tracednsip": dns_server,
            "tracednsName": hostname,
            "qtype": record_type,
        }

        return await self._trigger_diagnostic_call(
            check_url, data_url, payload, key, retries
        )
