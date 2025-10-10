"""Constants for Vodafone Station."""

import logging

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
DEVICE_SERCOMM_LOGIN_URL = "login.html"
DEVICE_SERCOMM_TOTAL_FIELDS_NUM = 8

DEVICE_TECHNICOLOR_LOGIN_URL = "api/v1/login_conf"
DEVICE_TECHNICOLOR_USER_ALREADY_LOGGED_IN = "MSG_LOGIN_150"

DEVICE_ULTRAHUB_LOGIN_URL = "/api/config/details.jst"
