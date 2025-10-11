"""Constants for Vodafone Station."""

import logging
from typing import Any

from aiohttp import ClientTimeout

_LOGGER = logging.getLogger(__package__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
    ),
    "Accept-Language": "en-GB,en;q=0.5",
    "X-Requested-With": "XMLHttpRequest",
    "Priority": "u=1",
}
DEFAULT_TIMEOUT = ClientTimeout(10)
POST_RESTART_TIMEOUT = ClientTimeout(2)

DEVICES_SETTINGS: dict[str, Any] = {
    "Sercomm": {
        "login_url": "login.html",
        "total_fields_num": 8,
    },
    "Technicolor": {
        "login_url": "api/v1/login_conf",
        "user_already_logged_in": "MSG_LOGIN_150",
    },
}

DEVICE_SERCOMM_LOGIN_STATUS = [
    "not logged",
    "logged",
    "already logged",
    "credential error",
    "credential error",
    "password mismatch",
    "incorrect challenge",
    "password mismatch",
]
