"""aiovodafone library."""

__version__ = "0.11.0"

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
    "AlreadyLogged",
    "CannotAuthenticate",
    "CannotConnect",
    "ModelNotSupported",
    "VodafoneError",
    "VodafoneStationDevice",
    "VodafoneStationSercommApi",
    "VodafoneStationTechnicolorApi",
]
