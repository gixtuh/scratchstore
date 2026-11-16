from __future__ import annotations

import base64
import html
import json
import logging
import re
import random
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Callable, Iterable

__version__ = "0.3.0"

LOG = logging.getLogger("scratchstore")

# Two-digit, one-based line numbers from list.txt. The mapping is shared with
# the Scratch client; every supported character has exactly one code.
_SOURCE_LINES = list("abcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()_+{}|:\"<>?-=[]\\;',./`~ ")
CHAR_TO_CODE: dict[str, str] = {
    char: f"{line_number:02d}"
    for line_number, char in enumerate(_SOURCE_LINES, start=1)
}
CODE_TO_CHAR: dict[str, str] = {
    code: char for char, code in CHAR_TO_CODE.items()
}

CLOUD_VALUE_LIMIT = 256
SEED_LENGTH = 5
SEED_MIN = 10_000
SEED_MAX = 99_999
FRAME_DATA_LIMIT = 250  # full 250 encoded digits; cloud storage preserves leading zeroes
RESPONSE_PAGE_LANES = 9
RESPONSE_PAGE_CHARACTER_CAPACITY = (FRAME_DATA_LIMIT // 2) * RESPONSE_PAGE_LANES
RESPONSE_PAGE_DELAY_SECONDS = 1.0
RESPONSE_LANE_NAMES = tuple(f"FH_{i}" for i in range(1, 10))
REQUEST_VARIABLE = "TH"
RESERVED = set(":|;\\")


class ScratchStoreError(Exception):
    """Base exception for ScratchStore."""


class NewScratcherError(ScratchStoreError):
    """Raised when the configured Scratch account is still a New Scratcher."""


class UnsupportedCharacterError(ScratchStoreError):
    """Raised when a string contains a character absent from the supplied map."""


class ProtocolError(ScratchStoreError):
    """Raised for malformed protocol packets or requests."""


class ScratchAuthenticationError(ScratchStoreError):
    """Raised when Scratch rejects a login or session validation request."""


def encode_text(text: str) -> str:
    """Encode text as two decimal digits per character using list.txt's map."""
    out: list[str] = []
    # The wire alphabet intentionally contains lowercase letters only. Normalize
    # text here as a final guard for usernames and any other mixed-case metadata.
    for char in str(text).lower():
        code = CHAR_TO_CODE.get(char)
        if code is None:
            raise UnsupportedCharacterError(
                f"Character {char!r} is not in list.txt's encoding map."
            )
        out.append(code)
    encoded = "".join(out)
    if len(encoded) % 2:
        raise AssertionError("The encoder produced an odd-length stream.")
    return encoded


def decode_text(encoded: str) -> str:
    """Decode an even-length digit stream made by encode_text()."""
    if len(encoded) % 2:
        raise ProtocolError("Encoded streams must contain an even number of digits.")
    if encoded and not encoded.isdigit():
        raise ProtocolError("Encoded streams may contain decimal digits only.")
    out: list[str] = []
    for pos in range(0, len(encoded), 2):
        code = encoded[pos:pos + 2]
        char = CODE_TO_CHAR.get(code)
        if char is None:
            raise ProtocolError(f"Unknown character code {code!r}.")
        out.append(char)
    return "".join(out)


def escape_field(value: Any) -> str:
    """Escape protocol delimiters in a database/key/value field."""
    text = str(value)
    return "".join(("\\" + ch) if ch in RESERVED else ch for ch in text)


def split_escaped(text: str, delimiter: str, *, maxsplit: int = -1) -> list[str]:
    """Split on unescaped delimiters while keeping escape pairs intact."""
    if len(delimiter) != 1:
        raise ValueError("delimiter must be one character")
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    splits = 0
    for char in text:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter and (maxsplit < 0 or splits < maxsplit):
            parts.append("".join(current))
            current.clear()
            splits += 1
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    parts.append("".join(current))
    return parts


def unescape_field(text: str) -> str:
    """Remove backslash escaping from one protocol field."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "\\" and i + 1 < len(text):
            i += 1
        out.append(text[i])
        i += 1
    return "".join(out)


def _decode_scratch_session_id(session_id: str) -> dict[str, Any]:
    """Decode the username/token payload embedded in Scratch's session cookie.

    This follows scratchattach's ``decode_session_id`` implementation:
    ``<base64-json>:<base62-timestamp>:<signature>``. Some session IDs use a
    zlib-compressed first component, indicated by the ``".`` prefix.
    """
    parts = str(session_id).split(":")
    if len(parts) != 3:
        raise ScratchAuthenticationError(
            "Scratch returned a session cookie with an unexpected format."
        )

    first = parts[0]
    try:
        # Match scratchattach's exact padding convention. The cookie can
        # retain surrounding quote characters, which the base64 decoder skips.
        decoded = base64.urlsafe_b64decode(first + "==")
        if first.startswith('".'):
            decoded = zlib.decompress(decoded)
        payload = json.loads(decoded.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, zlib.error) as exc:
        raise ScratchAuthenticationError(
            "Scratch returned a session cookie whose embedded data could not be decoded."
        ) from exc

    if not isinstance(payload, dict):
        raise ScratchAuthenticationError("Scratch's session cookie did not contain a JSON object.")
    if not isinstance(payload.get("username"), str) or not payload["username"]:
        raise ScratchAuthenticationError("Scratch's session cookie did not contain a username.")
    if not isinstance(payload.get("token"), str) or not payload["token"]:
        raise ScratchAuthenticationError("Scratch's session cookie did not contain an X-Token.")
    return payload


def _extract_session_cookie(response: Any, http_session: Any) -> str | None:
    """Extract scratchsessionsid while preserving quotes used by Scratch."""
    set_cookie = getattr(response, "headers", {}).get("Set-Cookie", "") or ""
    match = re.search(
        r'(?:^|[,;]\s*)scratchsessionsid=("[^"]+"|[^;,\s]+)',
        set_cookie,
        flags=re.IGNORECASE,
    )
    if match:
        return match.group(1).strip()

    # Requests' cookie jar is a useful fallback when Set-Cookie was normalized.
    try:
        value = http_session.cookies.get("scratchsessionsid")
        if value:
            return str(value)
    except Exception:
        pass
    try:
        value = response.cookies.get("scratchsessionsid")
        if value:
            return str(value)
    except Exception:
        pass
    return None


def _detect_new_scratcher_from_profile(http_session: Any, username: str, headers: dict[str, str], cookies: dict[str, str]) -> bool | None:
    """Fallback badge check using the public profile's group label.

    Scratchattach tracks this as a fallback because the public user API does
    not expose the ``permissions.new_scratcher`` field. The profile HTML
    structure is unofficial and may change, so ``None`` means inconclusive.
    """
    url = f"https://scratch.mit.edu/users/{urllib.parse.quote(username, safe='')}/"
    profile_headers = dict(headers)
    profile_headers.pop("X-Token", None)
    profile_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    try:
        response = http_session.get(url, headers=profile_headers, cookies=cookies, timeout=15)
        if response.status_code != 200:
            return None
        # Match the same visible group badge used by ScratchAttach's fallback
        # check. Strip nested HTML and decode entities before comparing.
        match = re.search(
            r'<span\b[^>]*class=["\'][^"\']*\bgroup\b[^"\']*["\'][^>]*>(.*?)</span>',
            response.text,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return None
        label = re.sub(r"<[^>]+>", " ", match.group(1))
        label = html.unescape(label).strip().casefold()
        if "new scratcher" in label:
            return True
        if "scratcher" in label:
            return False
    except Exception as exc:
        LOG.debug("Could not check the public Scratch profile badge: %s", exc)
    return None


def _split_cloud_value(value: Any) -> tuple[str, str] | None:
    """Return (payload, seed) from a cloud value ending in .12345."""
    raw = str(value).strip()
    payload, dot, seed = raw.rpartition(".")
    if not dot or len(seed) != SEED_LENGTH or not seed.isdigit():
        return None
    if len(payload) > 250 or len(payload) % 2 or not payload.isdigit():
        return None
    if not SEED_MIN <= int(seed) <= SEED_MAX:
        return None
    return payload, seed


@dataclass
class Database:
    """A JSON-backed database registered with ScratchStore."""
    name: str
    file: Path
    data: dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def __post_init__(self) -> None:
        self.name = str(self.name).lower()
        self.file = Path(self.file).expanduser()
        self._load_or_create()

    def _load_or_create(self) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)

        if not self.file.exists():
            self.data = {}
            self.save()
            return

        try:
            raw = json.loads(self.file.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ScratchStoreError(
                f"Database file {self.file} is not valid JSON: {exc}"
            ) from exc

        if not isinstance(raw, dict):
            raise ScratchStoreError(
                f"Database file {self.file} must contain a JSON object."
            )

        # Support and automatically migrate the previous ScratchStore format.
        legacy_format = raw.get("format") == "scratchstore"

        if legacy_format:
            source = raw.get("data")
            if not isinstance(source, dict):
                raise ScratchStoreError(
                    f"Legacy database file {self.file} contains invalid data."
                )
        else:
            source = raw

        normalized: dict[str, Any] = {}

        for key, value in source.items():
            lowered_key = str(key).lower()

            if lowered_key in normalized:
                raise ScratchStoreError(
                    f"Database file {self.file} contains keys that collide "
                    f"after lowercasing: {lowered_key!r}."
                )

            normalized_value = value.lower() if isinstance(value, str) else value
            normalized[lowered_key] = normalized_value

        self.data = normalized

        # Automatically migrate legacy files and normalize existing keys.
        if legacy_format or normalized != source:
            self.save()

    def save(self) -> None:
        with self._lock:
            temporary = self.file.with_name(self.file.name + ".tmp")

            temporary.write_text(
                json.dumps(
                    self.data,
                    ensure_ascii=False,
                    indent=2,
                    separators=(",", ":"),
                ),
                encoding="utf-8",
            )

            temporary.replace(self.file)

    def keys(self) -> list[str]:
        with self._lock:
            return list(self.data.keys())

    def get(self, key: str) -> Any:
        with self._lock:
            return self.data.get(str(key).lower(), None)

    def set(self, key: str, value: str) -> None:
        with self._lock:
            self.data[str(key).lower()] = str(value).lower()
            self.save()

    def delete(self, key: str) -> bool:
        normalized_key = str(key).lower()
        with self._lock:
            if normalized_key not in self.data:
                return False
            del self.data[normalized_key]
            self.save()
            return True


class _EventManager:
    """Thread-safe registry for the public ``@events.event`` decorator.

    Handler names identify their event. Currently supported handlers are
    ``on_set`` and ``on_get``. Decorating a function does not wrap or replace it.
    """

    _SUPPORTED = {"on_set", "on_get"}

    def __init__(self) -> None:
        self._handlers: dict[str, list[Callable[..., Any]]] = {
            name: [] for name in self._SUPPORTED
        }
        self._lock = threading.RLock()

    def event(self, function: Callable[..., Any]) -> Callable[..., Any]:
        if not callable(function):
            raise TypeError("@events.event can only decorate a callable")
        event_name = getattr(function, "__name__", "")
        if event_name not in self._SUPPORTED:
            supported = ", ".join(sorted(self._SUPPORTED))
            raise ValueError(
                f"Event handler must be named one of: {supported} (received {event_name!r})"
            )
        with self._lock:
            self._handlers[event_name].append(function)
        return function

    def _dispatch(self, event_name: str, *args: Any) -> None:
        with self._lock:
            handlers = tuple(self._handlers.get(event_name, ()))
        for handler in handlers:
            try:
                handler(*args)
            except Exception:
                LOG.exception("An %s event handler failed", event_name)


# Exposed as ``from scratchstore import events``.
events = _EventManager()


@dataclass
class _ProjectConfig:
    project_id: str
    username: str
    password: str


class _Connection:
    def __init__(self) -> None:
        self._project: _ProjectConfig | None = None
        self._databases: list[Database] = []
        self._lock = threading.RLock()

    def setup(self, _id: int | str, username: str, password: str) -> None:
        if isinstance(_id, bool) or not isinstance(_id, (int, str)):
            raise TypeError("_id must be a string or integer")
        if not str(_id).strip():
            raise ValueError("_id cannot be empty")
        if not username or not isinstance(username, str):
            raise ValueError("username must be a non-empty string")
        if not password or not isinstance(password, str):
            raise ValueError("password must be a non-empty string")
        with self._lock:
            self._project = _ProjectConfig(str(_id), username, password)

    def use(self, databases: Iterable[Database] | Database) -> None:
        if isinstance(databases, Database):
            databases = [databases]
        with self._lock:
            for database in databases:
                if not isinstance(database, Database):
                    raise TypeError("connection.use() expects Database objects returned by scratchstore.add()")
                database.name = str(database.name).lower()
                if any(existing.name.lower() == database.name for existing in self._databases):
                    raise ValueError(f"A database named {database.name!r} is already registered")
                self._databases.append(database)

    def snapshot(self) -> tuple[_ProjectConfig | None, list[Database]]:
        with self._lock:
            return self._project, list(self._databases)


class _Server:
    def __init__(
        self,
        project: _ProjectConfig,
        databases: list[Database],
        *,
        automatic: bool = True,
    ) -> None:
        self.project = project
        self.automatic = bool(automatic)
        self.databases = {database.name: database for database in databases}
        self._database_order = [database.name for database in databases]
        self._buffers: dict[str, dict[str, Any]] = {}
        self._buffer_lock = threading.RLock()
        self._response_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._queue: Queue[tuple[str, str] | None] = Queue()
        self._stop_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._receiver: threading.Thread | None = None
        self._http: Any = None
        self._session_id: str | None = None
        self._session_token: str | None = None
        self._authenticated_username: str | None = None
        self._new_scratcher: bool | None = None
        self._cookie_header: str | None = None
        self._ws: Any = None
        self._connection_ready = threading.Event()
        self._ignore_initial_th_snapshot = True
        self._last_response_seed: str | None = None

    def _authenticate(self) -> None:
        """Authenticate using Scratch's native login/session-cookie flow.

        This mirrors scratchattach's current implementation without importing
        scratchattach: POST /login/, extract scratchsessionsid, decode the
        username and X-Token from that cookie, then *optionally* refresh account
        permissions through POST /session (no trailing slash).
        """
        try:
            import requests
        except ImportError as exc:
            raise ScratchStoreError(
                "The requests package is missing. Run: python -m pip install -r requirements.txt"
            ) from exc

        http = requests.Session()
        csrf_token = "a"
        # These headers are based on scratchattach.utils.commons.headers and
        # scratchattach.site.session.login(). The Cookie header is important:
        # Scratch's login endpoint expects the CSRF cookie to match X-CSRFToken.
        login_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36"
            ),
            "X-CSRFToken": csrf_token,
            "X-Requested-With": "XMLHttpRequest",
            "Referer": "https://scratch.mit.edu",
            "Origin": "https://scratch.mit.edu",
            "Cookie": "scratchcsrftoken=a;scratchlanguage=en;",
        }
        LOG.info("Authenticating directly with Scratch as %s", self.project.username)

        try:
            # scratchattach's current login() uses /login/, not /accounts/login/.
            # It relies on Set-Cookie rather than treating the response body as
            # the authoritative source of the session.
            login_response = http.post(
                "https://scratch.mit.edu/login/",
                json={
                    "username": self.project.username,
                    "password": self.project.password,
                },
                headers=login_headers,
                timeout=20,
            )
        except requests.RequestException as exc:
            http.close()
            raise ScratchAuthenticationError(
                f"Could not contact Scratch's login endpoint: {exc}"
            ) from exc

        session_id = _extract_session_cookie(login_response, http)
        if not session_id:
            status = getattr(login_response, "status_code", "unknown")
            # Do not print response bodies here; login responses can contain
            # account/security details and should not be copied into logs.
            http.close()
            raise ScratchAuthenticationError(
                f"Scratch login did not provide a scratchsessionsid cookie (HTTP {status}). "
                "The credentials may be invalid, or Scratch may have challenged/blocked this request."
            )

        # scratchattach decodes this cookie immediately. In particular, the
        # X-Token is embedded in the cookie; it is not necessary to obtain it
        # from /session before opening the cloud WebSocket.
        try:
            session_payload = _decode_scratch_session_id(session_id)
        except ScratchAuthenticationError:
            http.close()
            raise
        actual_username = str(session_payload["username"])
        session_token = str(session_payload["token"])
        if actual_username.casefold() != self.project.username.casefold():
            LOG.warning(
                "Scratch authenticated as %s rather than the configured username %s",
                actual_username,
                self.project.username,
            )

        session_cookies = {
            "scratchsessionsid": session_id,
            "scratchcsrftoken": csrf_token,
            "scratchlanguage": "en",
        }
        session_headers = dict(login_headers)
        session_headers.pop("Cookie", None)
        session_headers["X-Token"] = session_token
        session_headers["Accept"] = "application/json"
        session_headers["Content-Type"] = "application/json"

        # This refresh is used only to obtain account permission metadata.
        # scratchattach's Session.update() posts to /session (no trailing
        # slash), with the decoded X-Token and session cookies. A failure here
        # must not discard an otherwise valid session cookie.
        new_scratcher: bool | None = None
        try:
            session_response = http.post(
                "https://scratch.mit.edu/session",
                headers=session_headers,
                cookies=session_cookies,
                timeout=20,
            )
            if session_response.status_code == 200:
                session_data = session_response.json()
                permissions = session_data.get("permissions", {}) if isinstance(session_data, dict) else {}
                user_data = session_data.get("user", {}) if isinstance(session_data, dict) else {}
                flag = permissions.get("new_scratcher") if isinstance(permissions, dict) else None
                if isinstance(flag, bool):
                    new_scratcher = flag
                refreshed_username = user_data.get("username") if isinstance(user_data, dict) else None
                if isinstance(refreshed_username, str) and refreshed_username:
                    actual_username = refreshed_username
                refreshed_token = user_data.get("token") if isinstance(user_data, dict) else None
                if isinstance(refreshed_token, str) and refreshed_token:
                    session_token = refreshed_token
                    session_headers["X-Token"] = refreshed_token
            else:
                LOG.warning(
                    "Scratch authenticated the session cookie, but POST /session returned HTTP %s; "
                    "permission metadata will be checked separately.",
                    session_response.status_code,
                )
        except (requests.RequestException, ValueError, TypeError) as exc:
            LOG.warning(
                "Scratch authenticated the session cookie, but account permissions could not be refreshed: %s",
                exc,
            )

        # /session is the authoritative source for permissions when available.
        # If it is unavailable (e.g. HTTP 403), use the public profile badge as
        # a best-effort fallback. An unknown result is not treated as proof that
        # the account is a New Scratcher or proof that it is a Scratcher.
        if new_scratcher is None:
            new_scratcher = _detect_new_scratcher_from_profile(
                http, actual_username, session_headers, session_cookies
            )

        if new_scratcher is True:
            http.close()
            self._new_scratcher = True
            raise NewScratcherError(
                "This account is a New Scratcher. Scratch cloud variables require Scratcher status."
            )
        if new_scratcher is None:
            LOG.warning(
                "Scratch login succeeded, but Scratch did not disclose the account's Scratcher badge status. "
                "Continuing with the authenticated session; the cloud server will determine whether cloud access is allowed."
            )

        self._http = http
        self._session_id = session_id
        self._session_token = session_token
        self._authenticated_username = actual_username
        self._new_scratcher = new_scratcher
        # scratchattach's ScratchCloud sends just the session cookie to the
        # cloud WebSocket, plus the Scratch origin. The X-Token is not a WS cookie.
        self._cookie_header = f"scratchsessionsid={session_id};"
        LOG.info("Logged into Scratch as %s", self._authenticated_username)
        LOG.info(
            "Scratch authentication succeeded",
            "unknown" if self._new_scratcher is None else self._new_scratcher,
        )

    def _open_cloud_socket(self) -> Any:
        """Open Scratch's real cloud WebSocket and send its project handshake."""
        try:
            import websocket
        except ImportError as exc:
            raise ScratchStoreError(
                "The websocket-client package is missing. Run: python -m pip install -r requirements.txt"
            ) from exc

        ws = None
        try:
            ws = websocket.create_connection(
                "wss://clouddata.scratch.mit.edu/",
                cookie=self._cookie_header,
                origin="https://scratch.mit.edu",
                timeout=5,
                enable_multithread=True,
            )
            handshake = {
                "method": "handshake",
                "user": self._authenticated_username,
                "project_id": self.project.project_id,
            }
            ws.send(json.dumps(handshake, separators=(",", ":")) + "\n")
            ws.settimeout(1.0)
        except Exception as exc:
            if ws is not None:
                try:
                    ws.close()
                except Exception:
                    pass
            raise ScratchStoreError(f"Could not connect to Scratch's cloud WebSocket: {exc}") from exc

        self._ws = ws
        self._connection_ready.set()
        self._ignore_initial_th_snapshot = True
        LOG.info("Connected to Scratch clouddata for project %s", self.project.project_id)
        return ws

    def connect(self) -> None:
        self._authenticate()
        self._open_cloud_socket()
        self._worker = threading.Thread(
            target=self._worker_loop, name="ScratchStore-worker", daemon=True
        )
        self._receiver = threading.Thread(
            target=self._receiver_loop, name="ScratchStore-cloud-receiver", daemon=True
        )
        self._worker.start()
        self._receiver.start()

    def _receiver_loop(self) -> None:
        """Read newline-delimited cloud events and reconnect if the socket drops."""
        try:
            import websocket
        except ImportError:
            return

        while not self._stop_event.is_set():
            ws = self._ws
            if ws is None:
                if not self.automatic:
                    self._stop_event.set()
                    break
                if self._stop_event.wait(0.5):
                    break
                try:
                    self._open_cloud_socket()
                except Exception as reconnect_error:
                    LOG.error("Scratch cloud reconnect failed: %s", reconnect_error)
                    self._stop_event.wait(3.0)
                continue
            try:
                message = ws.recv()
                if message is None or message == "":
                    raise ConnectionError("Scratch cloud WebSocket closed")
                for raw_line in str(message).splitlines():
                    if not raw_line.strip():
                        continue
                    try:
                        packet = json.loads(raw_line)
                    except json.JSONDecodeError:
                        LOG.debug("Ignoring non-JSON cloud frame: %r", raw_line[:160])
                        continue
                    if isinstance(packet, dict):
                        self._handle_cloud_packet(packet)
            except websocket.WebSocketTimeoutException:
                continue
            except Exception as exc:
                if self._stop_event.is_set():
                    break
                self._connection_ready.clear()
                try:
                    ws.close()
                except Exception:
                    pass
                if self._ws is ws:
                    self._ws = None

                if not self.automatic:
                    LOG.error("Scratch cloud socket disconnected; automatic reconnect is disabled")
                    self._stop_event.set()
                    break

                LOG.warning("Scratch cloud socket disconnected (%s); reconnecting", exc)
                self._stop_event.wait(1.0)
                if self._stop_event.is_set():
                    break
                try:
                    self._open_cloud_socket()
                except Exception as reconnect_error:
                    LOG.error("Scratch cloud reconnect failed: %s", reconnect_error)
                    self._stop_event.wait(3.0)

    def _lookup_log_username(self, variable_name: str, value: str) -> str | None:
        """Resolve the writer from Scratch's cloud activity log.

        Scratch's live WebSocket broadcasts variable updates without a writer
        field. The cloud log endpoint includes the actor, so match its newest
        exact name/value record instead of guessing the writer.
        """
        if self._http is None:
            return None
        normalized_name = variable_name if variable_name.startswith("☁ ") else f"☁ {variable_name}"
        for attempt in range(4):
            try:
                response = self._http.get(
                    "https://clouddata.scratch.mit.edu/logs",
                    params={"projectid": self.project.project_id, "limit": 50, "offset": 0},
                    timeout=10,
                )
                response.raise_for_status()
                records = response.json()
                if isinstance(records, list):
                    for record in records:
                        if not isinstance(record, dict):
                            continue
                        record_name = str(record.get("name", ""))
                        record_value = str(record.get("value", ""))
                        if record_name == normalized_name and record_value == value:
                            actor = record.get("user") or record.get("username")
                            if isinstance(actor, dict):
                                actor = actor.get("username")
                            if actor:
                                return str(actor)
                # The cloud log can briefly lag the live WebSocket event.
            except Exception as exc:
                LOG.debug("Cloud log actor lookup attempt %d failed: %s", attempt + 1, exc)
            if attempt < 3:
                time.sleep(0.12)
        return None

    def _handle_cloud_packet(self, packet: dict[str, Any]) -> None:
        if packet.get("method") != "set":
            return
        variable = str(packet.get("name", "")).removeprefix("☁ ")
        if variable != REQUEST_VARIABLE or "value" not in packet:
            return
        value = str(packet.get("value", ""))

        # The handshake sends the project's current variable values as an
        # initial snapshot. Do not mistake the old TH value for a new request.
        if self._ignore_initial_th_snapshot:
            self._ignore_initial_th_snapshot = False
            LOG.debug("Ignoring the initial TH cloud-variable snapshot")
            return

        username = packet.get("user") or packet.get("username")
        if not username:
            username = self._lookup_log_username(variable, value)
        if not username:
            LOG.warning("Could not resolve the Scratch username for a TH update; ignoring it")
            return

        parsed = _split_cloud_value(value)
        if parsed is None:
            LOG.debug("Ignoring malformed TH packet from %s", username)
            return
        payload, seed = parsed
        now = time.monotonic()
        completed: str | None = None
        with self._buffer_lock:
            username_key = str(username).lower()
            buffer = self._buffers.get(username_key)
            if buffer is None or now - buffer["updated"] > 8.0:
                buffer = {"parts": [], "seeds": set(), "updated": now}
                self._buffers[username_key] = buffer
            if seed in buffer["seeds"]:
                return
            buffer["seeds"].add(seed)
            buffer["parts"].append(payload)
            buffer["updated"] = now
            encoded = "".join(buffer["parts"])
            try:
                decoded = decode_text(encoded)
            except ProtocolError:
                LOG.warning("Discarding malformed request stream from %s", username)
                self._buffers.pop(username_key, None)
                return
            if decoded.endswith("stop:"):
                completed = decoded[:-5]
                self._buffers.pop(username_key, None)
        if completed is not None:
            self._queue.put((str(username), completed))

    def _worker_loop(self) -> None:
        """Process completed client requests and send their responses.

        The cloud receiver only assembles TH messages and places completed
        requests on ``self._queue``. This worker performs database operations
        serially so two requests cannot interleave their shared FH responses.
        """
        while not self._stop_event.is_set():
            try:
                item = self._queue.get(timeout=0.5)
            except Empty:
                continue

            try:
                if item is None:
                    return

                username, command = item
                try:
                    response = self._execute(command, username=username)
                except ProtocolError as exc:
                    LOG.warning("Invalid request from %s: %s", username, exc)
                    response = "error:bad_request"
                except UnsupportedCharacterError as exc:
                    LOG.warning("Unsupported data in request from %s: %s", username, exc)
                    response = "error:unsupported_character"
                except Exception:
                    # Keep detailed diagnostics on the host, but do not expose
                    # exception text or filesystem paths to Scratch clients.
                    LOG.exception("Request from %s failed", username)
                    response = "error:internal"

                try:
                    self._send_response(response, username)
                except Exception:
                    LOG.exception("Could not send the response to %s", username)
            finally:
                self._queue.task_done()

    def _send_cloud_values(self, values: dict[str, str]) -> None:
        """Send multiple cloud-variable set packets over our own WebSocket."""
        packets = []
        for variable, value in values.items():
            value = str(value)
            if len(value) > CLOUD_VALUE_LIMIT or not value.replace(".", "").replace("-", "").isnumeric():
                raise ProtocolError(f"Invalid Scratch cloud value for {variable!r}")
            packets.append({
                "method": "set",
                "user": self._authenticated_username,
                "project_id": self.project.project_id,
                "name": variable if variable.startswith("☁ ") else f"☁ {variable}",
                "value": value,
            })
        payload = "".join(json.dumps(packet, separators=(",", ":"), ensure_ascii=False) + "\n" for packet in packets)
        if not self._connection_ready.wait(timeout=10):
            raise ScratchStoreError("Scratch cloud WebSocket is not connected")
        with self._send_lock:
            ws = self._ws
            if ws is None:
                raise ScratchStoreError("Scratch cloud WebSocket disconnected before send")
            try:
                # One WebSocket frame can carry several newline-delimited JSON
                # cloud packets; this keeps an FH page together.
                ws.send(payload)
            except Exception as exc:
                self._connection_ready.clear()
                raise ScratchStoreError(f"Could not send cloud-variable updates: {exc}") from exc

    def _execute(self, command: str, username: str = "unknown") -> str:
        head = split_escaped(command, ":", maxsplit=1)
        if len(head) != 2:
            raise ProtocolError("Request is missing its command separator.")
        operation, raw_args = head
        actor = str(username).lower()

        if operation == "ping":
            LOG.info("Ping operation from %s", actor)
            return "pong"
        if operation == "getalldb":
            LOG.info("Get-all-databases operation from %s", actor)
            events._dispatch("on_get", 3, None, None, actor)
            return "|".join(escape_field(name) for name in self._database_order)

        raw_fields = split_escaped(raw_args, "|")
        fields = [unescape_field(field) for field in raw_fields]

        if operation == "set":
            if len(fields) != 3:
                raise ProtocolError("set requires database, key, and value")
            database = self._get_database(fields[0])
            LOG.info(
                "Set operation from %s: database=%s key=%s",
                actor, database.name, fields[1].lower(),
            )
            database.set(fields[1], fields[2])
            events._dispatch(
                "on_set", 1, database.name, fields[1].lower(), fields[2].lower(), actor
            )
            return "saved"

        if operation == "get":
            if len(fields) == 1:
                database = self._get_database(fields[0])
                LOG.info(
                    "Get-keys operation from %s: database=%s",
                    actor, database.name,
                )
                events._dispatch("on_get", 2, database.name, None, actor)
                return "|".join(escape_field(key) for key in database.keys())
            if len(fields) == 2:
                database = self._get_database(fields[0])
                LOG.info(
                    "Get-value operation from %s: database=%s key=%s",
                    actor, database.name, fields[1].lower(),
                )
                value = database.get(fields[1])
                if value is None:
                    return "not_found"
                events._dispatch("on_get", 1, database.name, fields[1].lower(), actor)
                return escape_field(value)
            raise ProtocolError("get requires a database, optionally followed by a key")

        if operation in {"del", "delete"}:
            if len(fields) != 2:
                raise ProtocolError("del requires database and key")
            database = self._get_database(fields[0])
            LOG.info(
                "Delete operation from %s: database=%s key=%s",
                actor, database.name, fields[1].lower(),
            )
            deleted_value = database.get(fields[1])
            deleted = database.delete(fields[1])
            if deleted:
                events._dispatch(
                    "on_set", 2, database.name, fields[1].lower(), deleted_value, actor
                )
                return "deleted"
            return "not_found"

        LOG.warning("Unknown operation from %s: %s", actor, operation)
        raise ProtocolError(f"Unknown operation {operation!r}")

    def _get_database(self, name: str) -> Database:
        database = self.databases.get(str(name).lower())
        if database is None:
            raise ProtocolError(f"Unknown database {name!r}")
        return database

    def _send_response(self, body: str, username: str) -> None:
        # Keep the two username fields separate: the first belongs to the data
        # response, while stop;username is the end-of-stream marker.
        # Scratch usernames can contain uppercase letters, but the wire alphabet
        # is deliberately lowercase. The client lowercases USERNAME() as well.
        username = str(username).lower()
        response_text = f"{str(body).lower()};username{username}stop;{username}"
        encoded = encode_text(response_text)
        chunks = [encoded[i:i + FRAME_DATA_LIMIT] for i in range(0, len(encoded), FRAME_DATA_LIMIT)]
        if not chunks:
            chunks = [""]

        with self._response_lock:
            for page_start in range(0, len(chunks), RESPONSE_PAGE_LANES):
                page_chunks = chunks[page_start:page_start + RESPONSE_PAGE_LANES]
                lane_count = len(page_chunks)
                # The first seed digit tells the Scratch client how many FH
                # lanes belong to this page. The remaining four digits keep
                # each page uniquely identifiable without touching unused lanes.
                seed = f"{lane_count}{random.randint(0, 9999):04d}"
                while seed == self._last_response_seed:
                    seed = f"{lane_count}{random.randint(0, 9999):04d}"
                self._last_response_seed = seed
                values: dict[str, str] = {}
                for lane_name, payload in zip(RESPONSE_LANE_NAMES, page_chunks):
                    # Only write populated lanes; later FH variables retain
                    # their previous values and are ignored by the client.
                    value = f"{payload}.{seed}"
                    if len(value) > CLOUD_VALUE_LIMIT:
                        raise AssertionError("A cloud value exceeded Scratch's 256-character limit")
                    values[lane_name] = value
                self._send_cloud_values(values)
                # Nine 250-digit lanes carry 1,125 decoded characters per page.
                # Wait exactly one second only when another FH_1..FH_9 page
                # remains to be sent; the final page is not followed by this delay.
                has_another_page = page_start + RESPONSE_PAGE_LANES < len(chunks)
                if has_another_page:
                    assert len(response_text) > RESPONSE_PAGE_CHARACTER_CAPACITY
                    time.sleep(RESPONSE_PAGE_DELAY_SECONDS)
            # Leave the final response visible briefly before the next queued
            # request overwrites the shared FH variables.
            time.sleep(1)

    def run_forever(self) -> None:
        self.connect()
        LOG.info("ScratchStore is running. Press Ctrl+C to stop.")
        try:
            while not self._stop_event.wait(0.5):
                pass
        except KeyboardInterrupt:
            LOG.info("Stopping ScratchStore...")
        finally:
            self.stop()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._queue.put_nowait(None)
        except Exception:
            pass
        self._connection_ready.clear()
        ws = self._ws
        self._ws = None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        for thread in (self._receiver, self._worker):
            if thread is not None and thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=2.0)
        if self._http is not None:
            try:
                self._http.close()
            except Exception:
                pass


def add(name: str, file: str | Path) -> Database:
    """Open an existing JSON database or create an empty one."""
    if not isinstance(name, str) or not name:
        raise ValueError("name must be a non-empty string")
    return Database(name=name, file=Path(file))


connection = _Connection()
_active_server: _Server | None = None


def start(verbose: bool = False, automatic: bool = True) -> None:
    """Start the ScratchStore connection.

    Args:
        verbose: Enable informational server logs when true.
        automatic: Reconnect to the cloud WebSocket after disconnects when true.
    """
    global _active_server
    if not isinstance(verbose, bool):
        raise TypeError("verbose must be a bool")
    if not isinstance(automatic, bool):
        raise TypeError("automatic must be a bool")

    project, databases = connection.snapshot()
    if project is None:
        raise ScratchStoreError(
            "Call scratchstore.connection.setup(...) before scratchstore.start()."
        )
    if not databases:
        raise ScratchStoreError(
            "Register at least one database with scratchstore.connection.use(databases=[...])."
        )
    if len(databases) > 100:
        raise ScratchStoreError("This version supports up to 100 databases.")

    # Keep application-provided logging configuration intact.
    if not logging.getLogger().handlers:
        logging.basicConfig(
            level=logging.INFO if verbose else logging.WARNING,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )
    LOG.setLevel(logging.INFO if verbose else logging.WARNING)

    _active_server = _Server(project, databases, automatic=automatic)
    _active_server.run_forever()


def stop() -> None:
    """Stop the active connection, if one is running."""
    if _active_server is not None:
        _active_server.stop()


__all__ = [
    "Database", "ScratchStoreError", "NewScratcherError",
    "UnsupportedCharacterError", "ProtocolError", "ScratchAuthenticationError",
    "connection", "events", "add", "start", "stop",
    "encode_text", "decode_text",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    print("ScratchStore server module imported successfully.")
    print("Configure scratchstore.connection, register databases, then call scratchstore.start().")