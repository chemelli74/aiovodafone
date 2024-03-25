"""Base tests for aiovodafone."""

from aiovodafone.api import (
    VodafoneStationDevice,
    VodafoneStationSercommApi,
    VodafoneStationTechnicolorApi,
)
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    ModelNotSupported,
    VodafoneError,
)


def test_objects_can_be_imported() -> None:
    """Verify objects exist."""
    assert type(VodafoneStationDevice)
    assert type(VodafoneStationSercommApi)
    assert type(VodafoneStationTechnicolorApi)
    assert type(VodafoneError)
    assert type(AlreadyLogged)
    assert type(CannotConnect)
    assert type(CannotAuthenticate)
    assert type(ModelNotSupported)
