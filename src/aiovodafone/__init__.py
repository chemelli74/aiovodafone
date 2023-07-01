__version__ = "0.0.2"

from .api import VodafoneStationDevice, VodafoneStationApi
from .exceptions import VodafoneError, CannotConnect, CannotAuthenticate

__all__ = [
    "VodafoneStationDevice",
    "VodafoneStationApi",
    "VodafoneError",
    "CannotConnect",
    "CannotAuthenticate",
]
