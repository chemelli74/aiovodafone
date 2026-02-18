"""Support for Vodafone Station."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from io import BytesIO
from typing import Any

import segno.helpers
from aiohttp import (
    ClientResponse,
    ClientResponseError,
    ClientSession,
    ClientTimeout,
)
from yarl import URL

from .const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    HEADERS,
    WifiBand,
    WifiType,
)
from .exceptions import (
    GenericResponseError,
)


@dataclass
class VodafoneStationDevice:
    """Vodafone Station device class."""

    connected: bool
    connection_type: str
    ip_address: str
    name: str
    mac: str
    type: str
    wifi: str


class VodafoneStationCommonApi(ABC):
    """Common API calls for Vodafone Station routers."""

    def __init__(
        self,
        url: URL,
        username: str,
        password: str,
        session: ClientSession,
    ) -> None:
        """Initialize the scanner."""
        self.username = username
        self.password = password
        self.base_url = url
        self.headers = HEADERS
        self.session = session
        self.csrf_token: str = ""
        self.encryption_key: str = ""
        self.salt: str = ""
        self._unique_id: str | None = None
        self._overview: dict[str, Any] = {}
        self._devices: dict[str, VodafoneStationDevice] = {}

    async def _set_cookie(self) -> None:
        """Enable required session cookie."""
        self.session.cookie_jar.update_cookies(
            SimpleCookie(f"domain={self.base_url.host}; name=login_uid; value=1;"),
        )

    async def _request_page_result(
        self,
        method: str,
        page: str,
        payload: dict[str, Any] | str | None = None,
        timeout: ClientTimeout = DEFAULT_TIMEOUT,
    ) -> ClientResponse:
        """Request data from a web page."""
        _LOGGER.debug("%s page %s from host %s", method, page, self.base_url.host)
        timestamp = int(datetime.now(tz=UTC).timestamp())
        url = self.base_url.joinpath(page).with_query(
            _=timestamp, csrf_token=self.csrf_token
        )
        try:
            response = await self.session.request(
                method,
                url,
                data=payload,
                headers=self.headers,
                timeout=timeout,
                ssl=False,
                allow_redirects=True,
            )
            if response.status != HTTPStatus.OK:
                _LOGGER.warning(
                    "%s page %s from host %s failed: %s",
                    method,
                    page,
                    self.base_url.host,
                    response.status,
                )
                raise GenericResponseError
        except ClientResponseError as err:
            _LOGGER.exception(
                "%s page %s from host %s failed", method, page, self.base_url.host
            )
            raise GenericResponseError from err
        else:
            return response

    async def _generate_guest_qr_code(
        self,
        ssid: str,
        password: str,
        security: str,
    ) -> BytesIO:
        """Get Wi-Fi Guest QR code."""
        settings = {
            "kind": "png",
            "scale": 4,
            "border": 0,
        }
        qr_code = segno.helpers.make_wifi(
            ssid=ssid,
            password=password,
            security=security,
            hidden=False,
        )
        stream = BytesIO()
        qr_code.save(
            out=stream,
            kind=settings["kind"],
            scale=settings["scale"],
            border=settings["border"],
        )
        stream.seek(0)
        return stream

    @abstractmethod
    def convert_uptime(self, uptime: str) -> datetime:
        """Convert uptime to datetime."""

    @abstractmethod
    async def login(self, force_logout: bool = False) -> bool:
        """Router login."""

    @abstractmethod
    async def get_devices_data(self) -> dict[str, VodafoneStationDevice]:
        """Get router device data."""

    @abstractmethod
    async def get_sensor_data(self) -> dict[str, Any]:
        """Get router sensor data."""

    @abstractmethod
    async def get_docis_data(self) -> dict[str, Any]:
        """Get router docis data."""

    @abstractmethod
    async def get_voice_data(self) -> dict[str, Any]:
        """Get router voice data."""

    @abstractmethod
    async def restart_connection(self, connection_type: str) -> None:
        """Internet Connection restart."""

    @abstractmethod
    async def restart_router(self) -> None:
        """Router restart."""

    @abstractmethod
    async def logout(self) -> None:
        """Router logout."""

    @abstractmethod
    async def get_wifi_data(
        self,
    ) -> dict[str, Any]:
        """Get Wi-Fi data."""

    @abstractmethod
    async def set_wifi_status(
        self, enable: bool, wifi_type: WifiType, band: WifiBand
    ) -> None:
        """Enable/Disable Wi-Fi."""
