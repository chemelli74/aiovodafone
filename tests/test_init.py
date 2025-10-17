"""Base tests for aiovodafone."""

from aiovodafone.api import (
    VodafoneStationCommonApi,
    VodafoneStationDevice,
)
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    GenericResponseError,
    ModelNotSupported,
    VodafoneError,
)


def test_objects_can_be_imported() -> None:
    """Verify objects exist."""
    assert type(AlreadyLogged)
    assert type(CannotAuthenticate)
    assert type(CannotConnect)
    assert type(GenericLoginError)
    assert type(GenericResponseError)
    assert type(ModelNotSupported)
    assert type(VodafoneError)
    assert type(VodafoneStationCommonApi)
    assert type(VodafoneStationDevice)
