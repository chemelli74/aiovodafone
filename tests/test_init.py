from aiovodafone.api import VodafoneStationApi, VodafoneStationDevice
from aiovodafone.exceptions import CannotAuthenticate, CannotConnect, VodafoneError


def test_objects_can_be_imported():
    assert VodafoneStationDevice
    assert VodafoneStationApi
    assert VodafoneError
    assert CannotConnect
    assert CannotAuthenticate
