"""Vodafone UK Technicolor device API implementation."""

import asyncio
import datetime as dt
import hmac
import re
from collections.abc import Iterator
from http import HTTPMethod
from typing import TYPE_CHECKING, Any

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import _LOGGER
from aiovodafone.exceptions import GenericLoginError

if TYPE_CHECKING:
    from aiohttp import ClientResponse
    from yarl import URL

import hashlib
import os
from typing import Final

# SRP-6 constants
_GEN: Final = 2
_K: Final = int(
    "ac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050"
    "a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50"
    "e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b8"
    "55f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773b"
    "ca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748"
    "544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6"
    "af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb6"
    "94b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73",
    16,
)
_C: Final = int("05b9e8ef059c6b32ea59fc1d322d37f04aa30bae5aa9003b8321e21ddb04e300", 16)
_U: Final = "4a76a9a2402bdd18123389b72ebbda50a30f65aedb90d7273130edea4b29cc4c"

# The byte-length of the modulus K
_K_LEN_BYTES: Final = 256

# Regular expressions for converting uptime string
_UPTIME_PATTERNS = {
    "days": re.compile(r"(\d+)\s*days?"),
    "hours": re.compile(r"(\d+)\s*hours?"),
    "minutes": re.compile(r"(\d+)\s*minutes?"),
    "seconds": re.compile(r"(\d+)\s*seconds?"),
}


def _sha256_hex(data: bytes) -> str:
    """Calculate SHA256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def _sha256_bytes(data: bytes) -> bytes:
    """Calculate SHA256 hash and return as bytes."""
    return hashlib.sha256(data).digest()


class TechnicolorSRP:
    """Technicolor SRP authentication client."""

    def __init__(self, username: str, password: str) -> None:
        """Initialize the SRP client.

        Args:
            username: The username for authentication.
            password: The password for authentication.

        """
        self.username = username
        self.password = password
        self._f_private, self._d_public = self._generate_client_ephemeral()

        # These will be calculated during the flow
        self._client_proof: str | None = None
        self._server_verification: str | None = None
        self._session_key_hash: str | None = None

    @staticmethod
    def _generate_client_ephemeral() -> tuple[int, int]:
        """Generate client's private (F) and public (D) values."""
        rand_bytes = os.urandom(32)
        f_private = int.from_bytes(rand_bytes, byteorder="big")

        # Calculate D = GEN^F mod K
        d_public = pow(_GEN, f_private, _K)

        return f_private, d_public

    @property
    def client_public_key_hex(self) -> str:
        """Return the client public key (D) as a hex string."""
        d_hex = f"{self._d_public:x}"
        if len(d_hex) % 2 == 1:
            return "0" + d_hex
        return d_hex

    def calculate_proofs(self, salt: str, server_public: str) -> str:
        """Calculate session key and authentication proofs.

        Args:
            salt: Salt received from server (hex string).
            server_public: Server's public value B (hex string).

        Returns:
            The client_proof (M) to be sent to the server.

        Raises:
            RuntimeError: If called more than once.
            ValueError: If server provides an invalid public key (B % K == 0)
                        or h == 0.

        """
        if self._client_proof is not None:
            msg = "Proofs have already been calculated."
            raise RuntimeError(msg)

        # Parse server public key B and perform safety check
        b_int = int(server_public, 16)
        if b_int % _K == 0:
            msg = "Invalid server public key (B % K == 0)."
            raise ValueError(msg)

        # Calculate h = SHA256(pad(D) || pad(B))
        d_bytes = self._d_public.to_bytes(_K_LEN_BYTES, byteorder="big")
        b_bytes = b_int.to_bytes(_K_LEN_BYTES, byteorder="big")

        h_bytes = _sha256_bytes(d_bytes + b_bytes)
        h_int = int.from_bytes(h_bytes, byteorder="big")

        # Perform second safety check
        if h_int == 0:
            msg = "Invalid scrambling parameter (h == 0)."
            raise ValueError(msg)

        # Calculate n = SHA256(salt + SHA256(username + ":" + password))
        password_hash = _sha256_bytes(f"{self.username}:{self.password}".encode())
        n_input = bytes.fromhex(salt + password_hash.hex())
        n_bytes = _sha256_bytes(n_input)
        n_int = int.from_bytes(n_bytes, byteorder="big")

        # Calculate a = (C * GEN^n) mod K
        a_int = (_C * pow(_GEN, n_int, _K)) % _K

        # Calculate b = (h * n + F) mod K
        b_value = (h_int * n_int + self._f_private) % _K

        # Calculate session key: g = (B - a)^b mod K
        g_int = pow((b_int - a_int) % _K, b_value, _K)

        # Convert g to hex string (with even length)
        g_hex = f"{g_int:x}"
        if len(g_hex) % 2 == 1:
            g_hex = "0" + g_hex

        # Calculate session key hash B_hash = SHA256(g)
        g_bytes = bytes.fromhex(g_hex)
        self._session_key_hash = _sha256_hex(g_bytes)

        # --- Calculate client proof (M) ---
        d_hex = self.client_public_key_hex
        username_hash = _sha256_hex(self.username.encode())

        y_input = bytes.fromhex(
            _U + username_hash + salt + d_hex + server_public + self._session_key_hash
        )
        self._client_proof = _sha256_hex(y_input)

        # --- Calculate server verification (v) ---
        v_input = bytes.fromhex(d_hex + self._client_proof + self._session_key_hash)
        self._server_verification = _sha256_hex(v_input)

        return self._client_proof

    def verify_server(self, server_proof: str) -> bool:
        """Verify the server's proof (M2).

        Args:
            server_proof: The proof string (M) sent by the server.

        Returns:
            True if the server's proof is valid, False otherwise.

        Raises:
            RuntimeError: If calculate_proofs has not been called first.

        """
        if self._server_verification is None:
            msg = (
                "Server verification value not calculated. Call calculate_proofs first."
            )
            raise RuntimeError(msg)

        return hmac.compare_digest(
            self._server_verification.upper(), server_proof.upper()
        )

    @property
    def session_key_hash(self) -> str:
        """Get the calculated session key hash (B_hash).

        Raises:
            RuntimeError: If calculate_proofs has not been called first.

        """
        if self._session_key_hash is None:
            msg = "Session key hash not calculated. Call calculate_proofs first."
            raise RuntimeError(msg)
        return self._session_key_hash


class VodafoneStationHomewareApi(VodafoneStationCommonApi):
    """API for Vodafone routers running Vantiva Homeware-based firmware.

    This module implements support for the UK Vodafone Ultra Hub and WiFi Hub routers.
    It may well support other countries and models too. Source code suggests it will
    also work for Vodafone routers in Australia, New Zealand and Spain.

    The common denominator is likely that they all run skinned Vantiva (formerly
    Technicolor) Homeware, a firmware based on OpenWRT and skinned by the ISP.
    They authenticate using a custom version of SRP 6 common among Technicolor routers.

    Tested on:
     - UK Vodafone Ultra Hub (DGM4980) - firmware v22
     - UK VOX 3.0 (THG3000) - firmware v19
    """

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
        _LOGGER.debug(await auth1_reply.text())
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
        _LOGGER.debug(await auth2_reply.text())

        auth2_response = await auth2_reply.json()
        server_proof = auth2_response.get("M")

        if not server_proof:
            msg = "Invalid response from second authentication request"
            raise GenericLoginError(msg)

        if not srp.verify_server(server_proof):
            msg = "Server authentication failed - proof mismatch"
            raise GenericLoginError(msg)

        _LOGGER.debug("Auth cookies set: %s", list(auth2_reply.cookies.keys()))

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
            wifi_data = await wifi_reply.json()
            eth_data = await eth_reply.json()
            data = {**wifi_data, **eth_data}
        devices: Iterator[VodafoneStationDevice | None] = map(
            self._parse_device, self._iterate_devices(data)
        )
        return {device.mac: device for device in devices if device is not None}

    async def get_sensor_data(self) -> dict[str, str]:
        """Fetch router system information."""
        sysinfo_reply, interfaces_reply = await asyncio.gather(
            self._request_url_result(
                HTTPMethod.GET,
                self.base_url.joinpath("modals/status-support/status.lp").with_query(
                    {"status": "systemInfo"}
                ),
            ),
            self._request_url_result(
                HTTPMethod.GET,
                self.base_url.joinpath("modals/status-support/restart.lp").with_query(
                    {"getInterfaceValues": "true"}
                ),
            ),
        )
        sysinfo: dict[str, Any] = (await sysinfo_reply.json()).get("systemParams", {})
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

    def convert_uptime(self, uptime: str) -> dt.datetime:
        """Parse human-readable uptime string to exact boot time.

        Accepts strings like:
        - '24 days, 15 hours, 1 minute and 41 seconds'
        - '5 minutes and 41 seconds'
        - '41 seconds'
        """
        components: dict[str, int] = {
            key: int(match.group(1)) if (match := pattern.search(uptime)) else 0
            for key, pattern in _UPTIME_PATTERNS.items()
        }

        # Ensure at least one component was parsed
        if not any(components.values()) and "0" not in uptime:
            msg = f"Failed to parse uptime string: {uptime!r}"
            raise ValueError(msg)

        delta = dt.timedelta(**components)
        boot_time = dt.datetime.now(tz=dt.UTC) - delta

        # strip sub-second accuracy, the uptime string is accurate to the second only
        return boot_time.replace(microsecond=0)
