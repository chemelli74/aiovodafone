"""aiovodafone library."""

__version__ = "0.6.1"

from .api import (
    VodafoneStationDevice,
    VodafoneStationSercommApi,
    VodafoneStationTechnicolorApi,
)
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    ModelNotSupported,
    VodafoneError,
)

__all__ = [
    "VodafoneStationDevice",
    "VodafoneStationSercommApi",
    "VodafoneStationTechnicolorApi",
    "VodafoneError",
    "AlreadyLogged",
    "CannotConnect",
    "CannotAuthenticate",
    "ModelNotSupported",
]
