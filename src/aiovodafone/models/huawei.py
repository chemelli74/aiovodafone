# Copyright 2023 Simone Chemelli and contributors
# SPDX-License-Identifier: Apache-2.0
"""Huawei (PT Vodafone) ONT / Station model API implementation."""

from __future__ import annotations

import base64
import contextlib
import re
from datetime import UTC, datetime, timedelta
from http import HTTPMethod, HTTPStatus
from typing import Any
from urllib.parse import urlencode

import aiohttp
from aiohttp import ClientResponseError, ClientSession
from yarl import URL

from aiovodafone.api import VodafoneStationCommonApi, VodafoneStationDevice
from aiovodafone.const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    POST_RESTART_TIMEOUT,
    REQUEST_TIMEOUT,
    WIFI_DATA,
    WifiBand,
    WifiType,
)
from aiovodafone.exceptions import (
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    GenericResponseError,
)

# WLANConfiguration instance mapping for PTVDF firmware.
_WLAN_INDEX: dict[tuple[WifiType, WifiBand], int] = {
    (WifiType.MAIN, WifiBand.BAND_2_4_GHZ): 1,
    (WifiType.GUEST, WifiBand.BAND_2_4_GHZ): 2,
    (WifiType.MAIN, WifiBand.BAND_5_GHZ): 5,
    (WifiType.GUEST, WifiBand.BAND_5_GHZ): 6,
}

_WIFI_ENTRY_KEY: dict[tuple[WifiType, WifiBand], str] = {
    (WifiType.MAIN, WifiBand.BAND_2_4_GHZ): "main",
    (WifiType.GUEST, WifiBand.BAND_2_4_GHZ): "guest",
    (WifiType.MAIN, WifiBand.BAND_5_GHZ): "main_5g",
    (WifiType.GUEST, WifiBand.BAND_5_GHZ): "guest_5g",
}

_BEACON_SECURITY = {
    "11i": "WPA2",
    "WPAand11i": "WPA",
    "WPA3": "WPA3",
    "11iandWPA3": "WPA2",
    "Basic": "WEP",
    "None": "nopass",
}

_USER_DEVICE_FIELDS = (
    "Domain",
    "IpAddr",
    "MacAddr",
    "Port",
    "IpType",
    "DevType",
    "DevStatus",
    "PortType",
    "Time",
    "HostName",
    "IPv4Enabled",
    "IPv6Enabled",
    "DeviceType",
    "UserDevAlias",
    "UserSpecifiedDeviceType",
    "LeaseTimeRemaining",
    "RealMacAddr",
)

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UPTIME_RE = re.compile(
    r"(?:(?P<days>\d+)\s*day(?:s)?\s*)?"
    r"(?P<hours>\d{1,2}):(?P<minutes>\d{2})(?::(?P<seconds>\d{2}))?",
    re.IGNORECASE,
)
_STRING_ARG_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ONTTOKEN_RE = re.compile(
    r"""(?:name|id)=["']onttoken["'][^>]*value=["']([^"']*)["']"""
    r"""|value=["']([^"']*)["'][^>]*(?:name|id)=["']onttoken["']""",
    re.I,
)
_PRODUCT_NAME_RE = re.compile(r"productName\s*=\s*'((?:\\x[0-9a-fA-F]{2}|[^'])*)'")
# index.asp: stDeviceInfo(domain, SoftwareVersion, UpTimeStr)
_DEVICE_INFO_RE = re.compile(
    r'new\s+stDeviceInfo\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)'
)
# Status_ptvdf.asp: stDeviceInfo(domain, Serial, HW, SW, Description, UpTimeSeconds)
_STATUS_DEVICE_INFO_RE = re.compile(
    r'new\s+stDeviceInfo\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,\s*"([^"]*)"\s*,'
    r'\s*"([^"]*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*"([^"]*)"\s*\)'
)
_CPU_USED_RE = re.compile(r"var\s+cpuUsed\s*=\s*'([^']*)'")
_MEM_USED_RE = re.compile(r"var\s+memUsed\s*=\s*'([^']*)'")
_LINE_URI_RE = re.compile(r'new\s+stLineURI\(\s*"[^"]*"\s*,\s*"([^"]*)"\s*\)')
_WAN_IP_RE = re.compile(r"new\s+WanIP\((.*?)\)\s*(?:,|;|\))", re.S)


def _decode_js_string(value: str) -> str:
    """Decode Huawei ASP ``\\xNN`` escapes and strip BOM."""
    return _HEX_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), value).lstrip(
        "\ufeff"
    )


def _parse_ctor_args(args_blob: str) -> list[str]:
    """Return decoded string arguments from a JS constructor call."""
    return [_decode_js_string(match.group(1)) for match in _STRING_ARG_RE.finditer(args_blob)]


def _parse_ctor_calls(script: str, ctor_name: str) -> list[list[str]]:
    """Parse all ``new Ctor(...)`` calls with the given constructor name.

    Matches the named constructor only (not outer ``new Array(...)`` wrappers),
    so nested ``new stWlan(...)`` entries inside arrays are all found.
    """
    pattern = re.compile(
        rf"new\s+{re.escape(ctor_name)}\((.*?)\)(?=\s*[,;)])",
        re.S,
    )
    calls: list[list[str]] = []
    for match in pattern.finditer(script):
        args = _parse_ctor_args(match.group(1))
        if args:
            calls.append(args)
    return calls


def _wlan_instance(domain: str) -> int | None:
    """Extract WLANConfiguration instance number from a TR-069 domain."""
    match = re.search(r"WLANConfiguration\.(\d+)", domain)
    if not match:
        return None
    return int(match.group(1))


class VodafoneStationHuaweiApi(VodafoneStationCommonApi):
    """Queries Huawei-based Vodafone Station / ONT web UI (PTVDF firmware)."""

    def __init__(
        self,
        url: URL,
        username: str,
        password: str,
        session: ClientSession,
    ) -> None:
        """Initialize Huawei API client."""
        super().__init__(url, username, password, session)
        self._session_cookie: str | None = None
        self._product_name: str = ""
        self._language: str = "english"

    def convert_uptime(self, uptime: str) -> datetime:
        """Convert Huawei uptime string to last-boot datetime.

        Accepts:
        - ``1 day(s) 05:09:51``
        - ``05:09:51``
        - integer seconds as string
        """
        cleaned = uptime.strip()
        if cleaned.isdigit():
            return datetime.now(tz=UTC) - timedelta(seconds=int(cleaned))

        match = _UPTIME_RE.fullmatch(cleaned.replace("(s)", "s"))
        if not match:
            # Fallback: try day(s) prefix + h:m:s with flexible spacing
            match = _UPTIME_RE.search(cleaned)
        if not match:
            _LOGGER.warning("Unable to parse Huawei uptime %r", uptime)
            return datetime.now(tz=UTC)

        days = int(match.group("days") or 0)
        hours = int(match.group("hours") or 0)
        minutes = int(match.group("minutes") or 0)
        seconds = int(match.group("seconds") or 0)
        return datetime.now(tz=UTC) - timedelta(
            days=days, hours=hours, minutes=minutes, seconds=seconds
        )

    async def login(self, force_logout: bool = False) -> bool:  # noqa: ARG002
        """Log into the router.

        The one-time token from ``GetRandCount.asp`` is bound to the TCP
        connection it was issued on. Token fetch and ``login.cgi`` are performed
        on a dedicated single-connection session so they share a socket even when
        the shared ClientSession uses a multi-connection pool.
        """
        _LOGGER.debug("Logging into %s", self.base_url.host)
        self._session_cookie = None
        self.csrf_token = ""

        language = self._language or "english"
        origin = str(self.base_url).rstrip("/")
        connector = aiohttp.TCPConnector(limit=1, force_close=False)
        try:
            async with aiohttp.ClientSession(
                connector=connector, cookie_jar=aiohttp.DummyCookieJar()
            ) as login_session:
                # Login page exposes productName used as model.
                with contextlib.suppress(ClientResponseError, TimeoutError, AttributeError):
                    login_page = await login_session.request(
                        HTTPMethod.GET,
                        self.base_url.joinpath(""),
                        headers={
                            "User-Agent": self.headers["User-Agent"],
                            "Accept": "text/html,*/*",
                            "Accept-Encoding": "identity",
                        },
                        timeout=DEFAULT_TIMEOUT,
                        ssl=False,
                        allow_redirects=False,
                    )
                    if login_page.status == HTTPStatus.OK:
                        page_text = await login_page.text()
                        product_match = _PRODUCT_NAME_RE.search(page_text)
                        if product_match:
                            self._product_name = _decode_js_string(
                                product_match.group(1)
                            )

                try:
                    token_response = await login_session.request(
                        HTTPMethod.POST,
                        self.base_url.joinpath("asp/GetRandCount.asp"),
                        data=b"",
                        headers={
                            "User-Agent": self.headers["User-Agent"],
                            "Accept": "*/*",
                            "Accept-Encoding": "identity",
                            "Origin": origin,
                            "Referer": f"{origin}/",
                            "X-Requested-With": "XMLHttpRequest",
                            "Content-Length": "0",
                        },
                        timeout=DEFAULT_TIMEOUT,
                        ssl=False,
                        allow_redirects=False,
                    )
                except ClientResponseError as err:
                    raise CannotConnect from err

                if token_response.status != HTTPStatus.OK:
                    raise CannotConnect(
                        f"GetRandCount.asp failed with status {token_response.status}"
                    )

                token = (await token_response.text()).lstrip("\ufeff").strip()
                if not token:
                    raise GenericLoginError("Empty login token from GetRandCount.asp")

                payload = urlencode(
                    {
                        "UserName": self.username,
                        "PassWord": base64.b64encode(self.password.encode()).decode(),
                        "Language": language,
                        "x.X_HW_Token": token,
                    }
                )

                try:
                    login_response = await login_session.request(
                        HTTPMethod.POST,
                        self.base_url.joinpath("login.cgi"),
                        data=payload,
                        headers={
                            "User-Agent": self.headers["User-Agent"],
                            "Accept": (
                                "text/html,application/xhtml+xml,application/xml;"
                                "q=0.9,*/*;q=0.8"
                            ),
                            "Accept-Encoding": "identity",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": origin,
                            "Referer": f"{origin}/",
                            "Upgrade-Insecure-Requests": "1",
                            "Cookie": f"Cookie=body:Language:{language}:id=-1",
                        },
                        timeout=DEFAULT_TIMEOUT,
                        ssl=False,
                        allow_redirects=False,
                    )
                except ClientResponseError as err:
                    raise CannotConnect from err

                headers = login_response.headers
                set_cookie_value = ""
                if hasattr(headers, "getall"):
                    values = headers.getall("Set-Cookie", []) or headers.getall(
                        "set-cookie", []
                    )
                    set_cookie_value = values[0] if values else ""
                else:
                    set_cookie_value = (
                        headers.get("Set-Cookie")
                        or headers.get("set-cookie")
                        or ""
                    )
                await login_response.read()
        finally:
            await connector.close()

        if not set_cookie_value or "sid=" not in set_cookie_value:
            raise CannotAuthenticate

        # Keep the raw ``Cookie=sid=...:Language:...:id=1`` header value. The
        # cookie *name* is literally ``Cookie``, which aiohttp's jar mangles.
        self._session_cookie = set_cookie_value.split(";", 1)[0]
        self.session.cookie_jar.clear()

        with contextlib.suppress(GenericResponseError, ClientResponseError, GenericLoginError):
            await self._refresh_onttoken()

        _LOGGER.debug("Logged into %s", self.base_url.host)
        return True

    async def _refresh_onttoken(self) -> None:
        """Load a page that embeds ``onttoken`` and store it as csrf_token."""
        text = await self._request_text("html/amp/ptvdf/vdfWlanBasicNew.asp")
        match = _ONTTOKEN_RE.search(text)
        if not match:
            # index.asp also carries device info; try overview as fallback later.
            text = await self._request_text("index.asp")
            match = _ONTTOKEN_RE.search(text)
        if match:
            self.csrf_token = match.group(1) or match.group(2) or ""
            _LOGGER.debug("onttoken refreshed")

    def _auth_headers(self, *, referer: str | None = None) -> dict[str, str]:
        """Build request headers including the session cookie."""
        if not self._session_cookie:
            raise GenericLoginError("Not authenticated")
        headers = {
            **self.headers,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
            "Cookie": self._session_cookie,
            "Origin": str(self.base_url).rstrip("/"),
            "Referer": referer
            or f"{str(self.base_url).rstrip('/')}/index.asp",
        }
        return headers

    async def _request_text(
        self,
        page: str,
        *,
        method: str = HTTPMethod.GET,
        payload: dict[str, Any] | str | None = None,
        additional_params: dict[str, Any] | None = None,
    ) -> str:
        """Perform an authenticated request and return decoded body text."""
        timeout = (additional_params or {}).get(REQUEST_TIMEOUT, DEFAULT_TIMEOUT)
        url = self.base_url.joinpath(page)
        _LOGGER.debug("%s page %s host %s", method, page, self.base_url.host)
        try:
            response = await self.session.request(
                method,
                url,
                data=payload,
                headers=self._auth_headers(),
                timeout=timeout,
                ssl=False,
                allow_redirects=False,
            )
        except ClientResponseError as err:
            raise GenericResponseError(f"Client response error: {err!s}") from err

        if response.status == HTTPStatus.FORBIDDEN:
            raise GenericLoginError("Session expired (HTTP 403)")
        if response.status != HTTPStatus.OK:
            raise GenericResponseError(
                f"{method} {page} failed with status {response.status}"
            )
        return _decode_js_string(await response.text())

    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Return connected/known LAN devices keyed by MAC address."""
        _LOGGER.debug("Getting devices host %s", self.base_url.host)
        text = await self._request_text(
            "html/bbsp/common/GetLanUserDevInfo.asp",
            method=HTTPMethod.POST,
            payload="",
        )
        devices: dict[str, VodafoneStationDevice] = {}
        for args in _parse_ctor_calls(text, "USERDevice"):
            fields = dict(zip(_USER_DEVICE_FIELDS, args, strict=False))
            mac = fields.get("MacAddr", "").lower()
            if not mac or mac in devices:
                continue
            port_type = (fields.get("PortType") or "").upper()
            connection_type = "WiFi" if port_type == "WIFI" else "Ethernet"
            hostname = (
                fields.get("HostName")
                or fields.get("UserDevAlias")
                or fields.get("IpAddr")
                or mac
            )
            devices[mac] = VodafoneStationDevice(
                connected=(fields.get("DevStatus") or "").lower() == "online",
                connection_type=connection_type,
                ip_address=fields.get("IpAddr") or "",
                name=hostname,
                mac=mac,
                type=fields.get("DevType") or port_type or "",
                wifi=fields.get("Port") or "",
            )
        self._devices = devices
        return devices

    async def get_sensor_data(self) -> dict[str, Any]:
        """Collect sensor values expected by the Home Assistant integration."""
        _LOGGER.debug("Getting sensor data for host %s", self.base_url.host)
        index_text = await self._request_text("index.asp")
        wan_text = await self._request_text(
            "html/bbsp/common/getwanlist.asp",
            method=HTTPMethod.POST,
            payload="",
        )

        # Only include keys with real values for numeric HA sensors. Empty
        # strings for data_rate / percentage keys crash entity updates
        # (ValueError on float("")) and make entities flap unavailable.
        data: dict[str, Any] = {
            "sys_serial_number": "",
            "sys_firmware_version": "",
            "sys_hardware_version": "",
            "sys_model_name": self._product_name,
            "sys_uptime": "",
            "fw_version": "",
            "wan_ip4_addr": "",
            "wan_ip6_addr": "",
            "inter_ip_address": "",
            "fiber_ipaddr": "",
            "fiber_ready": "0",
            "dsl_ipaddr": "",
            "dsl_ready": "0",
            "vf_internet_key_ip_addr": "",
            "phone_num1": "",
            "phone_num2": "",
            "sys_reboot_cause": "",
            "wan_status": "",
        }

        product_match = _PRODUCT_NAME_RE.search(index_text)
        if product_match:
            data["sys_model_name"] = _decode_js_string(product_match.group(1))
            self._product_name = data["sys_model_name"]

        device_info = _DEVICE_INFO_RE.search(index_text)
        if device_info:
            data["sys_firmware_version"] = device_info.group(2)
            data["fw_version"] = device_info.group(2)
            data["sys_uptime"] = device_info.group(3)

        # Status page: CPU/memory + full DeviceInfo (serial, HW, SW, uptime secs).
        with contextlib.suppress(GenericResponseError, GenericLoginError):
            status_text = await self._request_text(
                "html/bbsp/status/Status_ptvdf.asp"
            )
            if cpu_match := _CPU_USED_RE.search(status_text):
                cpu = cpu_match.group(1).strip()
                if cpu.endswith("%") and cpu[:-1].strip():
                    data["sys_cpu_usage"] = cpu
            if mem_match := _MEM_USED_RE.search(status_text):
                mem = mem_match.group(1).strip()
                if mem.endswith("%") and mem[:-1].strip():
                    data["sys_memory_usage"] = mem
            if status_info := _STATUS_DEVICE_INFO_RE.search(status_text):
                serial = _decode_js_string(status_info.group(2)).strip()
                hardware = _decode_js_string(status_info.group(3)).strip()
                software = _decode_js_string(status_info.group(4)).strip()
                description = _decode_js_string(status_info.group(5)).strip()
                uptime_secs = status_info.group(6).strip()
                if serial:
                    data["sys_serial_number"] = serial
                if hardware:
                    data["sys_hardware_version"] = hardware
                if software:
                    data["sys_firmware_version"] = software
                    data["fw_version"] = software
                if uptime_secs.isdigit():
                    data["sys_uptime"] = uptime_secs
                # Prefer short model from productName; fall back to description.
                if not data["sys_model_name"] and description:
                    data["sys_model_name"] = description.split("(")[0].strip()

        # Serial is not always exposed on user-level pages; use WAN MAC / model.
        internet_ip = ""
        wan_uptime = ""
        for args in (
            _parse_ctor_args(match.group(1))
            for match in _WAN_IP_RE.finditer(wan_text)
        ):
            if len(args) < 16:
                continue
            service = args[8] if len(args) > 8 else ""
            status = args[12] if len(args) > 12 else args[5]
            external_ip = args[15]
            uptime = args[43] if len(args) > 43 else ""
            if service.lower() == "internet":
                internet_ip = external_ip
                wan_uptime = uptime
                data["wan_status"] = status
                data["fiber_ipaddr"] = external_ip
                data["fiber_ready"] = (
                    "1" if status.lower() == "connected" else "0"
                )
                break

        data["wan_ip4_addr"] = internet_ip
        data["inter_ip_address"] = internet_ip
        if not data["sys_uptime"] and wan_uptime:
            data["sys_uptime"] = wan_uptime

        if not data["sys_model_name"] and self._product_name:
            data["sys_model_name"] = self._product_name

        # User-level UI often hides ONT serial; build a stable unique id.
        if not data["sys_serial_number"]:
            parts = [
                data["sys_model_name"] or self._product_name or "HUAWEI",
                internet_ip or (self.base_url.host or "ont"),
            ]
            data["sys_serial_number"] = "-".join(parts)

        if not data["sys_hardware_version"]:
            data["sys_hardware_version"] = (
                data["sys_model_name"] or self._product_name
            )

        # Phone numbers (optional page).
        with contextlib.suppress(GenericResponseError, GenericLoginError):
            phone_text = await self._request_text(
                "html/voip/vdfphonenumber/sipphonenumvdf.asp"
            )
            numbers = [
                num
                for num in (
                    _decode_js_string(m.group(1))
                    for m in _LINE_URI_RE.finditer(phone_text)
                )
                if num and not num.lower().startswith("line")
            ]
            if numbers:
                data["phone_num1"] = numbers[0]
            if len(numbers) > 1:
                data["phone_num2"] = numbers[1]

        # IPv6 WAN address when present.
        with contextlib.suppress(GenericResponseError, GenericLoginError):
            ipv6_text = await self._request_text(
                "html/bbsp/common/wanipv6state.asp"
            )
            for args in _parse_ctor_calls(ipv6_text, "IPv6AddressInfo"):
                if len(args) >= 4 and args[3] and args[3] != "::":
                    data["wan_ip6_addr"] = args[3]
                    break

        self._overview.update(data)
        return data

    async def get_wifi_data(self) -> dict[str, Any]:
        """Return Wi-Fi status / credentials for main and guest networks."""
        _LOGGER.debug("Getting Wi-Fi data host %s", self.base_url.host)
        overview = await self._request_text("overview.asp")
        psk_page = await self._request_text("html/amp/ptvdf/getWlanPsw.asp")

        # instance -> (enable, iface, ssid)
        # overview stWlan(domain, enable, iface, ssid) — args already decoded.
        ssids: dict[int, tuple[str, str, str]] = {}
        for args in _parse_ctor_calls(overview, "stWlan"):
            if len(args) < 4:
                continue
            instance = _wlan_instance(args[0])
            if instance is not None:
                ssids[instance] = (args[1], args[2], args[3])

        # getWlanPsw uses stWlan(domain, enable, name/iface, BeaconType)
        beacons: dict[int, str] = {}
        for args in _parse_ctor_calls(psk_page, "stWlan"):
            if len(args) < 4:
                continue
            instance = _wlan_instance(args[0])
            if instance is not None:
                beacons[instance] = args[3]
                if instance not in ssids:
                    ssids[instance] = (args[1], args[2], args[2])

        passwords: dict[int, str] = {}
        for args in _parse_ctor_calls(psk_page, "stPreSharedKey"):
            if len(args) < 2:
                continue
            instance = _wlan_instance(args[0])
            if instance is not None:
                passwords[instance] = args[1]

        wifi_data: dict[str, Any] = {WIFI_DATA: {}}
        for key, instance in (
            ((WifiType.MAIN, WifiBand.BAND_2_4_GHZ), 1),
            ((WifiType.GUEST, WifiBand.BAND_2_4_GHZ), 2),
            ((WifiType.MAIN, WifiBand.BAND_5_GHZ), 5),
            ((WifiType.GUEST, WifiBand.BAND_5_GHZ), 6),
        ):
            entry_key = _WIFI_ENTRY_KEY[key]
            enable, _iface, ssid = ssids.get(instance, ("0", "", ""))
            password = passwords.get(instance, "")
            security = _BEACON_SECURITY.get(beacons.get(instance, ""), "WPA2")
            entry: dict[str, Any] = {
                "on": int(enable == "1"),
                "ssid": ssid,
                "password": password,
                "security": security,
            }
            if key[0] == WifiType.GUEST and ssid:
                entry["qr_code"] = await self._generate_guest_qr_code(
                    ssid, password, security
                )
            wifi_data[WIFI_DATA][entry_key] = entry

        return wifi_data

    async def get_docis_data(self) -> dict[str, Any]:
        """DOCSIS is not applicable to this fiber ONT."""
        return {}

    async def get_voice_data(self) -> dict[str, Any]:
        """Return basic voice line data when available."""
        data: dict[str, Any] = {"line1": {}, "line2": {}, "general": {}}
        with contextlib.suppress(GenericResponseError, GenericLoginError):
            phone_text = await self._request_text(
                "html/voip/vdfphonenumber/sipphonenumvdf.asp"
            )
            numbers = [
                _decode_js_string(m.group(1))
                for m in _LINE_URI_RE.finditer(phone_text)
            ]
            for idx, number in enumerate(numbers[:2], start=1):
                if number and not number.lower().startswith("line"):
                    data[f"line{idx}"] = {"call_number": number}
        return data

    async def set_wifi_status(
        self,
        enable: bool,
        wifi_type: WifiType,
        band: WifiBand,
    ) -> None:
        """Enable or disable a Wi-Fi SSID."""
        _LOGGER.debug(
            "Switching %s Wi-Fi (%s) %s on %s",
            wifi_type,
            band,
            enable,
            self.base_url.host,
        )
        instance = _WLAN_INDEX.get((wifi_type, band))
        if instance is None:
            raise GenericResponseError(f"Unsupported wifi target {wifi_type}/{band}")

        if not self.csrf_token:
            await self._refresh_onttoken()
        if not self.csrf_token:
            raise GenericLoginError("Missing onttoken for Wi-Fi update")

        domain = f"InternetGatewayDevice.LANDevice.1.WLANConfiguration.{instance}"
        page = (
            f"set.cgi?x={domain}"
            f"&RequestFile=html/amp/ptvdf/vdfWlanBasicNew.asp"
        )
        payload = urlencode(
            {
                "x.Enable": "1" if enable else "0",
                "x.X_HW_Token": self.csrf_token,
            }
        )
        await self._request_text(
            page,
            method=HTTPMethod.POST,
            payload=payload,
        )
        # Token is single-use on many firmwares.
        self.csrf_token = ""
        with contextlib.suppress(GenericResponseError, GenericLoginError):
            await self._refresh_onttoken()

    async def restart_connection(self, connection_type: str) -> None:
        """Internet connection restart is not exposed on this firmware."""
        raise NotImplementedError(
            f"restart_connection({connection_type}) is not supported on Huawei ONT"
        )

    async def restart_router(self) -> None:
        """Reboot the router via DeviceInfo X_HW_Reboot when available."""
        _LOGGER.debug("Restarting router %s", self.base_url.host)
        if not self.csrf_token:
            await self._refresh_onttoken()
        if not self.csrf_token:
            raise GenericLoginError("Missing onttoken for reboot")

        # Common Huawei ONT reboot parameter. Some builds ignore unknown fields
        # without error; callers should treat this as best-effort.
        page = (
            "set.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SMP.DM"
            "&RequestFile=html/ssmp/cfgfile/cfgfileptvdf.asp"
        )
        payload = urlencode(
            {
                "x.X_HW_Command": "Reboot",
                "x.X_HW_Token": self.csrf_token,
            }
        )
        with contextlib.suppress(TimeoutError, GenericResponseError):
            await self._request_text(
                page,
                method=HTTPMethod.POST,
                payload=payload,
                additional_params={REQUEST_TIMEOUT: POST_RESTART_TIMEOUT},
            )
        self.csrf_token = ""
        self._session_cookie = None

    async def logout(self) -> None:
        """Log out and clear the local session cookie."""
        _LOGGER.debug("Logging out router %s", self.base_url.host)
        if self._session_cookie:
            with contextlib.suppress(Exception):
                await self.session.request(
                    HTTPMethod.GET,
                    self.base_url.joinpath("logout.cgi"),
                    headers=self._auth_headers(),
                    timeout=DEFAULT_TIMEOUT,
                    ssl=False,
                    allow_redirects=False,
                )
        self._session_cookie = None
        self.csrf_token = ""
        self.session.cookie_jar.clear()
