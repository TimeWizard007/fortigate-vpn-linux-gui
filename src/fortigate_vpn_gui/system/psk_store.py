# SPDX-License-Identifier: GPL-3.0-or-later
"""Store IPsec secrets in the desktop Secret Service.

The PSK authenticates the IKE/IPsec peer. The XAuth password authenticates the
user. Neither must be written to ``profiles.json``, logs, Diagnostics, or argv.

Storage uses the maintained ``keyring`` Secret Service / GNOME Keyring
interface. There is no custom encryption and no plaintext fallback.
Secrets are keyed by the stable profile id, not the visible profile name.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

PSK_SERVICE_NAME = "com.fortigate-vpn-linux-gui.ipsec-psk"
XAUTH_PASSWORD_SERVICE_NAME = "com.fortigate-vpn-linux-gui.ipsec-xauth-password"

UNAVAILABLE_MESSAGE = "Secure keyring unavailable. The PSK will be requested again at connect time."

PASSWORD_UNAVAILABLE_MESSAGE = (
    "Secure keyring unavailable. The XAuth password will be requested again at connect time."
)

MISSING_LIBRARY_MESSAGE = (
    "The Python keyring library is not installed in this environment. "
    "The PSK will be requested again at connect time."
)

MISSING_LIBRARY_PASSWORD_MESSAGE = (
    "The Python keyring library is not installed in this environment. "
    "The XAuth password will be requested again at connect time."
)

UNSUPPORTED_BACKEND_MESSAGE = (
    "No supported Secret Service / GNOME Keyring backend is available. "
    "The PSK will be requested again at connect time."
)

UNSUPPORTED_BACKEND_PASSWORD_MESSAGE = (
    "No supported Secret Service / GNOME Keyring backend is available. "
    "The XAuth password will be requested again at connect time."
)

LOCKED_MESSAGE = (
    "The desktop keyring is locked. Unlock it when GNOME prompts, "
    "or enter the secret each time you connect."
)

PSK_NOT_STORED_MESSAGE = (
    "The pre-shared key was not stored and will be required again at connect time."
)

SAVE_FAILED_MESSAGE = (
    "The desktop Secret Service could not save the secret. You can enter it each time you connect."
)

_SECURE_MARKERS = ("secretservice", "libsecret", "kwallet")
_INSECURE_MARKERS = ("plaintext", "file", "null")
_FAIL_MARKERS = ("backends.fail", ".fail")
_CHAINER_MARKERS = ("chainer",)


class PskStoreError(Exception):
    """Raised when a secret cannot be stored. The message is safe to show."""


@runtime_checkable
class PskStore(Protocol):
    """Lookup table for IPsec PSKs and XAuth passwords keyed by profile id."""

    def is_available(self) -> bool:
        """Return True when secrets can be stored and retrieved."""

    def unavailable_message(self) -> str:
        """Return a user-facing explanation when PSK storage is unavailable."""

    def password_unavailable_message(self) -> str:
        """Return a user-facing explanation when password storage is unavailable."""

    def get(self, profile_id: str) -> str | None:
        """Return the stored PSK, or None when absent or unreadable."""

    def set(self, profile_id: str, psk: str) -> None:
        """Store *psk* for *profile_id*. Never falls back to plaintext."""

    def delete(self, profile_id: str) -> None:
        """Remove a stored PSK. Missing entries are not an error."""

    def contains(self, profile_id: str) -> bool:
        """Return True when a PSK is stored for *profile_id*."""

    def get_xauth_password(self, profile_id: str) -> str | None:
        """Return the stored XAuth password, or None when absent."""

    def set_xauth_password(self, profile_id: str, password: str) -> None:
        """Store the XAuth password. Never falls back to plaintext."""

    def delete_xauth_password(self, profile_id: str) -> None:
        """Remove a stored XAuth password. Missing entries are not an error."""

    def contains_xauth_password(self, profile_id: str) -> bool:
        """Return True when an XAuth password is stored for *profile_id*."""

    def delete_all(self, profile_id: str) -> None:
        """Remove PSK and XAuth password for *profile_id*."""


class MemoryPskStore:
    """In-memory store for tests. Does not write files."""

    def __init__(self) -> None:
        self._secrets: dict[str, str] = {}
        self._passwords: dict[str, str] = {}

    def is_available(self) -> bool:
        return True

    def unavailable_message(self) -> str:
        return UNAVAILABLE_MESSAGE

    def password_unavailable_message(self) -> str:
        return PASSWORD_UNAVAILABLE_MESSAGE

    def get(self, profile_id: str) -> str | None:
        if not profile_id:
            return None
        return self._secrets.get(profile_id)

    def set(self, profile_id: str, psk: str) -> None:
        if not profile_id or not psk:
            raise PskStoreError("A profile identifier and pre-shared key are required.")
        self._secrets[profile_id] = psk

    def delete(self, profile_id: str) -> None:
        self._secrets.pop(profile_id, None)

    def contains(self, profile_id: str) -> bool:
        return bool(profile_id) and profile_id in self._secrets

    def get_xauth_password(self, profile_id: str) -> str | None:
        if not profile_id:
            return None
        return self._passwords.get(profile_id)

    def set_xauth_password(self, profile_id: str, password: str) -> None:
        if not profile_id or not password:
            raise PskStoreError("A profile identifier and XAuth password are required.")
        self._passwords[profile_id] = password

    def delete_xauth_password(self, profile_id: str) -> None:
        self._passwords.pop(profile_id, None)

    def contains_xauth_password(self, profile_id: str) -> bool:
        return bool(profile_id) and profile_id in self._passwords

    def delete_all(self, profile_id: str) -> None:
        self.delete(profile_id)
        self.delete_xauth_password(profile_id)


class UnavailablePskStore:
    """No-op store used when Secret Service cannot be used."""

    def __init__(
        self,
        message: str = UNAVAILABLE_MESSAGE,
        password_message: str = PASSWORD_UNAVAILABLE_MESSAGE,
    ) -> None:
        self._message = message
        self._password_message = password_message

    def is_available(self) -> bool:
        return False

    def unavailable_message(self) -> str:
        return self._message

    def password_unavailable_message(self) -> str:
        return self._password_message

    def get(self, profile_id: str) -> str | None:
        del profile_id
        return None

    def set(self, profile_id: str, psk: str) -> None:
        del profile_id, psk
        raise PskStoreError(self._message)

    def delete(self, profile_id: str) -> None:
        del profile_id

    def contains(self, profile_id: str) -> bool:
        del profile_id
        return False

    def get_xauth_password(self, profile_id: str) -> str | None:
        del profile_id
        return None

    def set_xauth_password(self, profile_id: str, password: str) -> None:
        del profile_id, password
        raise PskStoreError(self._password_message)

    def delete_xauth_password(self, profile_id: str) -> None:
        del profile_id

    def contains_xauth_password(self, profile_id: str) -> bool:
        del profile_id
        return False

    def delete_all(self, profile_id: str) -> None:
        del profile_id


@runtime_checkable
class _SecretServiceApi(Protocol):
    def get_password(self, service: str, username: str) -> str | None: ...

    def set_password(self, service: str, username: str, password: str) -> None: ...

    def delete_password(self, service: str, username: str) -> None: ...


class SecretServicePskStore:
    """PSK/XAuth store backed by the Linux Secret Service through ``keyring``."""

    def __init__(self, api: _SecretServiceApi | None = None) -> None:
        self._api = api

    def is_available(self) -> bool:
        api = self._resolve_api()
        if api is None:
            return False
        return _is_supported_secret_service(api, injected=self._api is not None)

    def unavailable_message(self) -> str:
        return self._unavailable_text(psk=True)

    def password_unavailable_message(self) -> str:
        return self._unavailable_text(psk=False)

    def get(self, profile_id: str) -> str | None:
        return self._get(PSK_SERVICE_NAME, profile_id)

    def set(self, profile_id: str, psk: str) -> None:
        self._set(PSK_SERVICE_NAME, profile_id, psk, "pre-shared key")

    def delete(self, profile_id: str) -> None:
        self._delete(PSK_SERVICE_NAME, profile_id)

    def contains(self, profile_id: str) -> bool:
        return self.get(profile_id) is not None

    def get_xauth_password(self, profile_id: str) -> str | None:
        return self._get(XAUTH_PASSWORD_SERVICE_NAME, profile_id)

    def set_xauth_password(self, profile_id: str, password: str) -> None:
        self._set(XAUTH_PASSWORD_SERVICE_NAME, profile_id, password, "XAuth password")

    def delete_xauth_password(self, profile_id: str) -> None:
        self._delete(XAUTH_PASSWORD_SERVICE_NAME, profile_id)

    def contains_xauth_password(self, profile_id: str) -> bool:
        return self.get_xauth_password(profile_id) is not None

    def delete_all(self, profile_id: str) -> None:
        self.delete(profile_id)
        self.delete_xauth_password(profile_id)

    def _unavailable_text(self, *, psk: bool) -> str:
        api = self._resolve_api()
        if api is None:
            return MISSING_LIBRARY_MESSAGE if psk else MISSING_LIBRARY_PASSWORD_MESSAGE
        if _is_supported_secret_service(api, injected=self._api is not None):
            return UNAVAILABLE_MESSAGE if psk else PASSWORD_UNAVAILABLE_MESSAGE
        return UNSUPPORTED_BACKEND_MESSAGE if psk else UNSUPPORTED_BACKEND_PASSWORD_MESSAGE

    def _get(self, service: str, profile_id: str) -> str | None:
        if not profile_id or not self.is_available():
            return None
        api = self._resolve_api()
        if api is None:
            return None
        try:
            secret = api.get_password(service, profile_id)
        except Exception:
            return None
        if not isinstance(secret, str) or not secret:
            return None
        return secret

    def _set(self, service: str, profile_id: str, secret: str, kind: str) -> None:
        if not profile_id or not secret:
            raise PskStoreError(f"A profile identifier and {kind} are required.")
        if not self.is_available():
            raise PskStoreError(self._unavailable_text(psk=service == PSK_SERVICE_NAME))
        api = self._resolve_api()
        if api is None:
            raise PskStoreError(self._unavailable_text(psk=service == PSK_SERVICE_NAME))
        try:
            api.set_password(service, profile_id, secret)
        except Exception as exc:
            if _is_locked_error(exc):
                raise PskStoreError(LOCKED_MESSAGE) from None
            raise PskStoreError(SAVE_FAILED_MESSAGE) from None

    def _delete(self, service: str, profile_id: str) -> None:
        if not profile_id:
            return
        api = self._resolve_api()
        if api is None:
            return
        try:
            api.delete_password(service, profile_id)
        except Exception:
            return

    def _resolve_api(self) -> _SecretServiceApi | None:
        if self._api is not None:
            return self._api
        return _load_secret_service_api()


def build_psk_store(*, api: _SecretServiceApi | None = None) -> PskStore:
    """Return Secret Service storage, or a no-op store when it is unavailable."""
    resolved = api if api is not None else _load_secret_service_api()
    if resolved is None:
        return UnavailablePskStore(MISSING_LIBRARY_MESSAGE, MISSING_LIBRARY_PASSWORD_MESSAGE)
    store = SecretServicePskStore(api=resolved)
    if store.is_available():
        return store
    return UnavailablePskStore(UNSUPPORTED_BACKEND_MESSAGE, UNSUPPORTED_BACKEND_PASSWORD_MESSAGE)


def default_psk_store() -> PskStore:
    """Construct the process-wide secret store."""
    return build_psk_store()


def _load_secret_service_api() -> _SecretServiceApi | None:
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _is_supported_secret_service(api: object, *, injected: bool = False) -> bool:
    """Allow Secret Service / KWallet, including a chainer that contains them."""
    getter = getattr(api, "get_keyring", None)
    if not callable(getter):
        return injected
    try:
        backend = getter()
    except Exception:
        return False
    return _backend_is_allowed(backend)


def _backend_is_allowed(backend: object) -> bool:
    if _is_secure_os_backend(backend):
        return True
    if _is_insecure_backend(backend) or _is_fail_backend(backend):
        return False
    if _is_chainer_backend(backend):
        children = _backend_children(backend)
        if not children:
            return False
        if any(_is_insecure_backend(item) for item in children):
            return False
        return any(_backend_is_allowed(item) for item in children)
    return False


def _backend_children(backend: object) -> tuple[object, ...]:
    for attr in ("backends", "keyrings"):
        raw = _attr_from_instance_or_class(backend, attr)
        if raw is None:
            continue
        if isinstance(raw, (list, tuple)):
            return tuple(raw)
        if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes)):
            return tuple(raw)
    return ()


def _attr_from_instance_or_class(backend: object, name: str) -> object:
    value = getattr(backend, name, None)
    if value is not None:
        return value
    return getattr(type(backend), name, None)


def _is_secure_os_backend(backend: object) -> bool:
    return _module_contains(backend, _SECURE_MARKERS)


def _is_insecure_backend(backend: object) -> bool:
    return _module_contains(backend, _INSECURE_MARKERS)


def _is_fail_backend(backend: object) -> bool:
    return _module_contains(backend, _FAIL_MARKERS)


def _is_chainer_backend(backend: object) -> bool:
    return _module_contains(backend, _CHAINER_MARKERS)


def _module_contains(backend: object, markers: tuple[str, ...]) -> bool:
    module = type(backend).__module__.casefold()
    return any(marker in module for marker in markers)


def _is_locked_error(exc: BaseException) -> bool:
    return type(exc).__name__ == "KeyringLocked"
