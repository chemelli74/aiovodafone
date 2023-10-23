"""Constants for Vodafone Station."""
import logging
from enum import Enum

_LOGGER = logging.getLogger(__package__)

LOGIN = [
    "-",
    "logged",
    "already logged",
    "credential error",
    "credential error",
    "password mismatch",
]

USER_ALREADY_LOGGED_IN = "MSG_LOGIN_150"


class DeviceType(str, Enum):
    SERCOMM = "Sercomm"
    TECHNICOLOR = "Technicolor"
