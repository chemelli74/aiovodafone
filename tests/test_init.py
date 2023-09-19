from aiovodafone.api import VodafoneStationApi, VodafoneStationDevice
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    ModelNotSupported,
    VodafoneError,
)


def test_objects_can_be_imported():
    assert type(VodafoneStationDevice)
    assert type(VodafoneStationApi)
    assert type(VodafoneError)
    assert type(AlreadyLogged)
    assert type(CannotConnect)
    assert type(CannotAuthenticate)
    assert type(ModelNotSupported)
