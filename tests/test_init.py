from aiovodafone.api import VodafoneStationApi, VodafoneStationDevice
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    ModelNotSupported,
    VodafoneError,
)


def test_objects_can_be_imported():
    assert VodafoneStationDevice
    assert VodafoneStationApi
    assert VodafoneError
    assert AlreadyLogged
    assert CannotConnect
    assert CannotAuthenticate
    assert ModelNotSupported
