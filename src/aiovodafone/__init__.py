"""aiovodafone library."""

__version__ = "1.2.0-rc.1"

from .api import (
    VodafoneStationDevice,
    VodafoneStationSercommApi,
    VodafoneStationTechnicolorApi,
)
from .exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    CsrfError,
    ModelNotSupported,
    VodafoneError,
)

__all__ = [
    "AlreadyLogged",
    "CannotAuthenticate",
    "CannotConnect",
    "CsrfError",
    "ModelNotSupported",
    "VodafoneError",
    "VodafoneStationDevice",
    "VodafoneStationSercommApi",
    "VodafoneStationTechnicolorApi",
]
