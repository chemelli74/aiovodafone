__version__ = "0.2.0"

from .api import VodafoneStationApi, VodafoneStationDevice
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    ModelNotSupported,
    VodafoneError,
)

__all__ = [
    "VodafoneStationDevice",
    "VodafoneStationApi",
    "VodafoneError",
    "AlreadyLogged",
    "CannotConnect",
    "CannotAuthenticate",
    "ModelNotSupported",
]
