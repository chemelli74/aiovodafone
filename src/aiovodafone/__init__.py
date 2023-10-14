__version__ = "0.3.2"

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
