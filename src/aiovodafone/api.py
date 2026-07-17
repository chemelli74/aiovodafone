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
)
from yarl import URL

from .const import (
    _LOGGER,
    DEFAULT_TIMEOUT,
    DEVICES_SETTINGS,
    HEADERS,
    REQUEST_ALLOW_REDIRECTS,
    REQUEST_SUPPRESS_LOG,
    REQUEST_TIMEOUT,
    WifiBand,
    WifiType,
)
from .exceptions import (
    CannotAuthenticate,
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

    device_type: str
    """String identifying the device type. Must be a valid key in DEVICES_SETTINGS."""

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
        query: dict[str, Any] | None = None,
        additional_params: dict[str, Any] | None = None,
    ) -> ClientResponse:
        """Request data from a web page."""
        _LOGGER.debug("%s page %s from host %s", method, page, self.base_url.host)
        query_params = (
            query
            if query is not None
            else {
                "_": int(datetime.now(tz=UTC).timestamp()),
                "csrf_token": self.csrf_token,
            }
        )

        # Additional parameters
        allow_redirects = (additional_params or {}).get(REQUEST_ALLOW_REDIRECTS, False)
        suppress_log = (additional_params or {}).get(REQUEST_SUPPRESS_LOG, False)
        timeout = (additional_params or {}).get(REQUEST_TIMEOUT, DEFAULT_TIMEOUT)

        url = self.base_url.joinpath(page)
        if query_params:
            url = url.with_query(query_params)
        try:
            response = await self.session.request(
                method,
                url,
                data=payload,
                headers=self.headers,
                timeout=timeout,
                ssl=False,
                allow_redirects=allow_redirects,
            )
            if response.status != HTTPStatus.OK:
                login_page = f"/{DEVICES_SETTINGS[self.device_type]['login_url']}"
                if (
                    response.status == HTTPStatus.FOUND
                    and response.headers
                    and response.headers.get("Location") == login_page
                ):
                    _LOGGER.debug(
                        "%s page %s from host %s redirects to login page '%s'",
                        method,
                        page,
                        self.base_url.host,
                        login_page,
                    )
                    raise CannotAuthenticate(
                        f"Client response redirect to login page '{login_page}'"
                    ) from None

                _LOGGER.warning(
                    "%s page %s from host %s failed: %s",
                    method,
                    page,
                    self.base_url.host,
                    response.status,
                )
                raise GenericResponseError
        except ClientResponseError as err:
            # Some models return text replies with invalid HTML headers.
            # Suppress expected errors to prevent log spam.
            if not suppress_log:
                _LOGGER.exception(
                    "%s page %s from host %s failed", method, page, self.base_url.host
                )
            raise GenericResponseError(f"Client response error: {err!s}") from err
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
