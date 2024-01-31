"""Constants for Vodafone Station."""
import logging
from enum import Enum

_LOGGER = logging.getLogger(__package__)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Accept-Language": "en-GB,en;q=0.5",
    "X-Requested-With": "XMLHttpRequest",
    "Accept:": "text/html,application/xhtml+xml,application/xml",
}

LOGIN = [
    "not logged",
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
    ARRIS = "Arris"
