__version__ = "0.0.2"

from .api import VodafoneStationApi, VodafoneStationDevice
from .exceptions import CannotAuthenticate, CannotConnect, VodafoneError

__all__ = [
    "VodafoneStationDevice",
    "VodafoneStationApi",
    "VodafoneError",
    "CannotConnect",
    "CannotAuthenticate",
]
