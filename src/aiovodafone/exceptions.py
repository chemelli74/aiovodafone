"""Vodafone Station library exceptions."""

from __future__ import annotations


class VodafoneError(Exception):
    """Base class for aiovodafone errors."""


class GenericLoginError(VodafoneError):
    """Exception raised when login fails."""


class GenericResponseError(VodafoneError):
    """Exception raised when GET/POST fails."""


class CannotConnect(VodafoneError):
    """Exception raised when connection fails."""


class CannotAuthenticate(VodafoneError):
    """Exception raised when credentials are incorrect."""


class AlreadyLogged(VodafoneError):
    """Exception raised if a user is already logged."""


class ModelNotSupported(VodafoneError):
    """Exception raised when using a model not yet supported."""


class ResultTimeoutError(VodafoneError):
    """Exception raised when a debug request times out."""


class CsrfError(VodafoneError):
    """Exception raised when a CSRF Error occurs."""
