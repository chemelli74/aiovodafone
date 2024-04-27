"""Constants for Vodafone Station."""

import logging
from enum import Enum

_LOGGER = logging.getLogger(__package__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
    ),
    "Accept-Language": "en-GB,en;q=0.5",
    "X-Requested-With": "XMLHttpRequest",
}

LOGIN = [
    "not logged",
    "logged",
    "already logged",
    "credential error",
    "credential error",
    "password mismatch",
    "incorrect challenge",
    "password mismatch",
]

USER_ALREADY_LOGGED_IN = "MSG_LOGIN_150"

FULL_FIELDS_NUM = 8


class DeviceType(str, Enum):
    """Supported device types."""

    SERCOMM = "Sercomm"
    TECHNICOLOR = "Technicolor"
