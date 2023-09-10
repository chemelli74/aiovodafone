"""Vodafone Station library exceptions."""
from __future__ import annotations


class VodafoneError(Exception):
    """Base class for aiovodafone errors."""


class CannotConnect(VodafoneError):
    """Exception raised when connection fails."""


class CannotAuthenticate(VodafoneError):
    """Exception raised when credentials are incorrect."""


class AlreadyLogged(VodafoneError):
    """Exception raised if a user is already logged."""


class ModelNotSupported(VodafoneError):
    """Exception raised when using a model not yet supported."""
