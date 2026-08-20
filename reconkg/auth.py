"""Authentication and target-address validation.

RC-06: every endpoint was anonymous. RC-04: `address` was any 253-character
string and got interpolated into event paths broadcast to every analyst
window.

Credentials come from the environment only -- RECONKG_TOKENS, formatted
`principal:token,principal:token`. Nothing is hardcoded and there is no
default token: with the variable unset the app refuses to start rather than
falling back to something permissive. A "dev mode" default is how an
unauthenticated coordinator ends up on a lab network.
"""

from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional

from fastapi import Header, HTTPException, WebSocket, status

log = logging.getLogger(__name__)

TOKEN_ENV = "RECONKG_TOKENS"
MIN_TOKEN_LEN = 16


class AuthError(RuntimeError):
    pass


class AuthzError(RuntimeError):
    """Authenticated, but not permitted."""


class Role(str, Enum):
    """Authorisation tiers, least to most privileged.

    The split follows who is allowed to *change what the graph believes*.
    A viewer reads; a scanner submits evidence for targets that already
    exist; an operator decides what is in scope at all; an admin manages
    the trust configuration itself. Evidence submission and scope definition
    are separated deliberately -- a scanner box running unattended in a lab
    is the credential most likely to leak, and it should not be able to
    invent new targets.
    """

    VIEWER = "viewer"
    SCANNER = "scanner"
    OPERATOR = "operator"
    ADMIN = "admin"

    @property
    def level(self) -> int:
        return ["viewer", "scanner", "operator", "admin"].index(self.value)

    def satisfies(self, required: "Role") -> bool:
        return self.level >= required.level


@dataclass(frozen=True)
class Principal:
    name: str
    role: Role
    scope: tuple[str, ...] = ()
    expires_at: Optional[datetime] = None
    """RC-20: standing credentials had no lifetime. A lab token issued once
    and pasted into a scanner unit file outlives the engagement it was cut
    for, and there was no way to retire it short of restarting the process
    with a different environment. Optional -- an unset expiry is still
    unlimited, but now it is a visible choice rather than the only option."""

    @property
    def expired(self) -> bool:
        return (self.expires_at is not None
                and datetime.now(timezone.utc) >= self.expires_at)

    @property
    def expires_in_days(self) -> Optional[float]:
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return round(delta.total_seconds() / 86400, 2)
    """Address patterns this principal may touch. Empty = unrestricted.

    RC-14: roles constrain the *kind* of action; scope constrains *where*.
    A leaked lab scanner token that can submit evidence for any address in
    the world is only half-contained. Patterns are CIDR blocks
    (10.10.10.0/24), exact addresses, or suffix wildcards (*.htb).
    """

    def may_touch(self, address: str) -> bool:
        if not self.scope:
            return True
        for pattern in self.scope:
            if _scope_matches(pattern, address):
                return True
        return False

    def __str__(self) -> str:  # provenance records the name only
        return self.name


def _scope_matches(pattern: str, address: str) -> bool:
    pattern = pattern.strip().lower()
    address = address.strip().lower()
    if not pattern:
        return False
    if pattern == "*":
        return True
    if pattern.startswith("*."):
        return address.endswith(pattern[1:])
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
        except ValueError:
            log.warning("ignoring unparseable scope pattern %r", pattern)
            return False
        try:
            return ipaddress.ip_address(address) in network
        except ValueError:
            return False        # a hostname never matches a CIDR
    return pattern == address


def load_principals(raw: Optional[str] = None) -> dict[str, Principal]:
    """Parse RECONKG_TOKENS into {token: Principal}.

    Entries are `name:role:token`. The two-field form `name:token` is still
    accepted and grants OPERATOR, because silently *downgrading* an existing
    deployment to read-only would look like a broken scanner rather than a
    policy change -- but it warns, loudly, every start.
    """
    raw = raw if raw is not None else os.environ.get(TOKEN_ENV, "")
    if not raw.strip():
        raise AuthError(
            f"{TOKEN_ENV} is unset. Set it to "
            "'analyst:viewer:<token>,box1:scanner:<token>' with tokens of at "
            "least 16 characters. There is no default.")
    principals: dict[str, Principal] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or ":" not in entry:
            raise AuthError(f"malformed entry in {TOKEN_ENV}: {entry!r}")
        parts = [p.strip() for p in entry.split(":")]
        scope: tuple[str, ...] = ()
        expires: Optional[datetime] = None
        if len(parts) == 2:
            name, token = parts
            role = Role.OPERATOR
            log.warning("principal %r has no role; defaulting to %s. Use "
                        "'name:role:token' to set one explicitly.",
                        name, role.value)
        elif len(parts) in (3, 4):
            name, role_raw, token = parts[0], parts[1], parts[2]
            try:
                role = Role(role_raw.lower())
            except ValueError:
                raise AuthError(
                    f"unknown role {role_raw!r} for {name!r}; expected one of: "
                    + ", ".join(r.value for r in Role)) from None
            if len(parts) == 4 and parts[3]:
                spec = parts[3]
                # Optional trailing "@YYYY-MM-DD" expiry on the scope field.
                if "@" in spec:
                    spec, _, expiry_raw = spec.rpartition("@")
                    try:
                        expires = datetime.strptime(
                            expiry_raw.strip(), "%Y-%m-%d").replace(
                                tzinfo=timezone.utc)
                    except ValueError:
                        raise AuthError(
                            f"bad expiry {expiry_raw!r} for {name!r}; "
                            "expected @YYYY-MM-DD") from None
                scope = tuple(p.strip() for p in spec.split(";") if p.strip())
        else:
            raise AuthError(f"malformed entry in {TOKEN_ENV}: {entry!r}")

        if not name or len(token) < MIN_TOKEN_LEN:
            raise AuthError(
                f"token for {name!r} must be >= {MIN_TOKEN_LEN} chars")
        if token in principals:
            raise AuthError("duplicate token: two principals cannot share one "
                            "credential, or independence accounting is a lie")
        principal = Principal(name=name, role=role, scope=scope,
                              expires_at=expires)
        if principal.expired:
            log.warning("principal %r expired on %s; its token will be "
                        "refused", name, expires.date())
        principals[token] = principal
    return principals


TICKET_TTL_SECONDS = 60
MAX_OUTSTANDING_TICKETS = 512
"""RC-18: unredeemed tickets accumulated without bound -- 5000 calls to
/api/ws-ticket retained 5000 entries. Expiry alone is not a cap when the
issue rate exceeds the TTL."""

MAX_TICKETS_PER_PRINCIPAL = 16
"""RC-26: the RC-18 cap evicted the oldest ticket in a table shared by every
principal, so 517 calls from the lowest-privilege credential in the system
evicted an operator's unredeemed ticket and closed its handshake 1008.

Bounding shared state without partitioning it converts a memory bug into a
cross-principal denial of service. A principal now has its own allowance and
overflows into itself: the table cannot fill with one caller's tickets, and
no caller's flood can reach another's. Sixteen is far above any legitimate
use -- a ticket is redeemed within a second of issue and lives 60."""


class Authenticator:
    """Bearer credentials, plus short-lived single-use WebSocket tickets.

    RC-12: browsers cannot set headers on a WebSocket handshake, so the only
    way to authenticate one from a browser is the query string -- and query
    strings land in proxy logs, server access logs and browser history. A
    long-lived bearer token there is a credential leak with a long tail.

    A ticket is obtained over authenticated REST, lives 60 seconds, and is
    consumed on first use. Leaking one costs you a minute of replay window
    against a socket you already opened, rather than your standing credential.
    """

    def __init__(self, principals: dict[str, Principal]) -> None:
        self._principals = principals
        self._tickets: dict[str, tuple[Principal, float]] = {}

    # -- tickets ------------------------------------------------------------- #

    def issue_ticket(self, principal: Principal) -> str:
        self._expire_tickets()
        # RC-26. Eviction is confined to the issuing principal's own tickets.
        # The previous rule -- drop the oldest ticket in the table -- was
        # written so an issuance flood could not lock out an operator, and had
        # exactly the opposite effect, because the flood's own tickets were
        # the newest ones in the table and everybody else's were the oldest.
        mine = [t for t, (owner, _) in self._tickets.items()
                if owner.name == principal.name]
        while len(mine) >= MAX_TICKETS_PER_PRINCIPAL:
            oldest = min(mine, key=lambda t: self._tickets[t][1])
            self._tickets.pop(oldest, None)
            mine.remove(oldest)
            log.warning("per-principal ticket cap reached for %s; evicting "
                        "its own oldest", principal.name)
        if len(self._tickets) >= MAX_OUTSTANDING_TICKETS:
            # The global cap is now a backstop for many principals rather than
            # a lever one of them can pull. Refuse rather than evict: taking
            # someone else's ticket is the failure this finding was about.
            log.warning("outstanding ticket table full; refusing issue for %s",
                        principal.name)
            raise AuthError("ticket table full; retry shortly")
        ticket = secrets.token_urlsafe(32)
        self._tickets[ticket] = (principal, time.monotonic() + TICKET_TTL_SECONDS)
        return ticket

    def redeem_ticket(self, ticket: Optional[str]) -> Principal:
        """Single use: the ticket is removed whether or not it was valid."""
        self._expire_tickets()
        if not ticket:
            raise AuthError("missing ticket")
        entry = self._tickets.pop(ticket, None)
        if entry is None:
            raise AuthError("invalid or already-used ticket")
        principal, expires = entry
        if time.monotonic() > expires:
            raise AuthError("ticket expired")
        return principal

    def _expire_tickets(self) -> None:
        now = time.monotonic()
        for ticket in [t for t, (_, exp) in self._tickets.items() if exp < now]:
            self._tickets.pop(ticket, None)

    def resolve(self, token: Optional[str]) -> Principal:
        """Constant-time lookup. Returns the principal or raises.

        Every candidate is compared even after a match so the loop takes the
        same time regardless of position in the table; expiry is checked
        after, on the resolved principal, for the same reason.
        """
        if not token:
            raise AuthError("missing credential")
        found: Optional[Principal] = None
        for known, principal in self._principals.items():
            if hmac.compare_digest(token, known):
                found = principal
        if found is None:
            raise AuthError("invalid credential")
        if found.expired:
            raise AuthError(
                f"credential for '{found.name}' expired on "
                f"{found.expires_at.date()}")
        return found

    def from_header(self, authorization: Optional[str]) -> Principal:
        """Absent and malformed are reported differently on purpose.

        Both used to raise the same message, so the RC-29 counter labelled a
        client that sent no credential at all identically to one that sent a
        broken header. "Nobody is authenticating" and "something is
        authenticating wrongly" are different operational signals, and a
        metric that cannot tell them apart is only half a metric.
        """
        if not authorization:
            raise AuthError("missing credential")
        if not authorization.lower().startswith("bearer "):
            raise AuthError("expected 'Authorization: Bearer <token>'")
        return self.resolve(authorization[7:].strip())


# --------------------------------------------------------------------------- #
# Target address validation (RC-04)
# --------------------------------------------------------------------------- #

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def validate_address(raw: str) -> str:
    """Accept an IPv4/IPv6 literal or a DNS hostname. Reject everything else.

    Rejecting by character class rather than escaping on output means the
    hostile string never enters the graph, so no downstream consumer -- event
    paths, log lines, a future HTML view -- has to remember to escape it.
    """
    if not isinstance(raw, str):
        raise ValueError("address must be a string")
    candidate = raw.strip()
    if not candidate or len(candidate) > 253:
        raise ValueError("address must be 1-253 characters")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in candidate):
        raise ValueError("address contains control characters")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    if _HOSTNAME.match(candidate):
        return candidate.lower()
    raise ValueError(f"not a valid IP address or hostname: {candidate!r}")


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #

_authenticator: Optional[Authenticator] = None


def configure(principals: Optional[dict[str, str]] = None) -> Authenticator:
    global _authenticator
    _authenticator = Authenticator(principals or load_principals())
    log.info("authentication configured for %d principals",
             len(set(_authenticator._principals.values())))
    return _authenticator


def current_authenticator() -> Authenticator:
    if _authenticator is None:
        raise AuthError("authenticator not configured")
    return _authenticator


_failure_hook: Optional[Callable[[str], None]] = None


def on_auth_failure(hook: Optional[Callable[[str], None]]) -> None:
    """Register an observer for refused credentials.

    The hook lives here rather than in a wrapper dependency because
    `require_role` resolves through `require_principal`, so a counting
    dependency bolted on beside it is simply never called -- which is how
    RC-29's counter sat at 0.0 while requests were being refused. One
    chokepoint, one hook.
    """
    global _failure_hook
    _failure_hook = hook


def _failure_reason(exc: AuthError) -> str:
    """Fixed vocabulary. The label must never carry attacker-supplied text."""
    text = str(exc).lower()
    if "missing" in text:
        return "missing"
    if "expired" in text:
        return "expired"
    if "expected" in text:
        return "malformed"
    return "invalid"


async def require_principal(
        authorization: Optional[str] = Header(default=None)) -> Principal:
    try:
        return current_authenticator().from_header(authorization)
    except AuthError as exc:
        if _failure_hook is not None:
            try:
                _failure_hook(_failure_reason(exc))
            except Exception:      # telemetry must never break the refusal
                log.exception("auth failure hook raised")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc),
                            headers={"WWW-Authenticate": "Bearer"}) from None


def require_scope(principal: Principal, address: str) -> None:
    """403 when a principal reaches outside its declared scope."""
    if not principal.may_touch(address):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"principal '{principal.name}' is scoped to "
            f"{', '.join(principal.scope)} and may not act on {address}")


def require_role(required: Role):
    """Dependency factory: 401 if unauthenticated, 403 if under-privileged.

    Distinguishing the two matters operationally -- 403 tells you the
    credential is real and the role is wrong, which is a config fix, not a
    hunt for a bad token.
    """

    async def dependency(
            authorization: Optional[str] = Header(default=None)) -> Principal:
        principal = await require_principal(authorization)
        if not principal.role.satisfies(required):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"role '{principal.role.value}' cannot perform this action; "
                f"'{required.value}' or higher required")
        return principal

    return dependency


async def require_principal_ws(websocket: WebSocket) -> Optional[str]:
    """WebSocket auth: bearer header, or a single-use ticket in the query.

    Raw tokens are no longer accepted as `?token=` -- see Authenticator for
    why. Closes 1008 on failure.
    """
    auth = current_authenticator()
    header = websocket.headers.get("authorization")
    try:
        if header and header.lower().startswith("bearer "):
            return auth.from_header(header)
        return auth.redeem_ticket(websocket.query_params.get("ticket"))
    except AuthError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return None
