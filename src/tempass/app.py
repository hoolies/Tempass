"""Create a temporary password, then reveal it once."""

import hmac
import os
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

PASSWORD_TTL_SECONDS = 172800
_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGITS = "0123456789"
_SYMBOLS = "!@#$%^&*-_=+"
_POOLS = {
    1: (_LOWERCASE,),
    2: (_LOWERCASE, _UPPERCASE),
    3: (_LOWERCASE, _UPPERCASE, _DIGITS),
    4: (_LOWERCASE, _UPPERCASE, _DIGITS, _SYMBOLS),
}
_SCHEMA = """
CREATE TABLE IF NOT EXISTS tempass (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    created_at INTEGER NOT NULL
)
"""

templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent / "templates"))


class GeneratedPassword(BaseModel):
    password: str
    token: str
    reveal_path: str
    expires_at: int = Field(description="Unix time when the reveal link stops working.")


def database_path() -> Path:
    """Return the SQLite file, independent of the process working directory."""
    configured = os.environ.get("TEMPASS_DB")
    if configured:
        return Path(configured).expanduser()
    return Path(__file__).resolve().parents[2] / "data" / "tempass.db"


def generate_password(length: int = 14, complexity: int = 4) -> str:
    """Return a password with at least one character from each selected class."""
    if complexity not in _POOLS:
        raise ValueError("complexity must be between 1 and 4")
    pools = _POOLS[complexity]
    if length < len(pools):
        raise ValueError("length must be at least the number of character classes")
    characters = [secrets.choice(pool) for pool in pools]
    alphabet = "".join(pools)
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    path = database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.isolation_level = None
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
    finally:
        connection.close()


def init_db() -> None:
    with _connection() as connection:
        connection.execute(_SCHEMA)


def store_password(token: str, password: str, created_at: int) -> bool:
    """Store a password and drop expired rows. Return False when the token exists."""
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DELETE FROM tempass WHERE created_at < ?",
                (created_at - PASSWORD_TTL_SECONDS,),
            )
            connection.execute(
                "INSERT INTO tempass (token, password, created_at) VALUES (?, ?, ?)",
                (token, password, created_at),
            )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            connection.execute("ROLLBACK")
            return False
        except Exception:
            connection.execute("ROLLBACK")
            raise
    return True


def consume_password(token: str) -> str | None:
    """Delete the password for this token and return it, once, if it is current."""
    now = int(time.time())
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "DELETE FROM tempass WHERE created_at < ?",
                (now - PASSWORD_TTL_SECONDS,),
            )
            row = connection.execute(
                "SELECT password FROM tempass WHERE token = ?",
                (token,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            deleted = connection.execute("DELETE FROM tempass WHERE token = ?", (token,))
            if deleted.rowcount != 1:
                connection.execute("ROLLBACK")
                return None
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
    return str(row["password"])


def _create_password(length: int, complexity: int) -> GeneratedPassword:
    now = int(time.time())
    password = generate_password(length, complexity)
    for _ in range(5):
        token = secrets.token_urlsafe(16)
        if store_password(token, password, now):
            return GeneratedPassword(
                password=password,
                token=token,
                reveal_path=f"/password/{token}",
                expires_at=now + PASSWORD_TTL_SECONDS,
            )
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not store a password")


def _keys_match(provided: str, expected: str) -> bool:
    return hmac.compare_digest(provided.encode(), expected.encode())


def require_api_key(provided: Annotated[str | None, Depends(_API_KEY_HEADER)]) -> None:
    expected = os.environ.get("TEMPASS_API_KEY", "")
    if not expected or provided is None or not _keys_match(provided, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


app = FastAPI(title="Tempass", lifespan=_lifespan)


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


@app.post("/generate", response_model=GeneratedPassword, dependencies=[Depends(require_api_key)])
def generate(
    length: Annotated[int, Query(ge=4, le=128)] = 14,
    complexity: Annotated[int, Query(ge=1, le=4)] = 4,
) -> GeneratedPassword:
    """Return a new password for the caller to set, plus a one-time reveal link."""
    return _create_password(length, complexity)


@app.get("/password/{token}", response_class=HTMLResponse)
def confirm_reveal(request: Request, token: str) -> HTMLResponse:
    """Show a confirmation page. This does not reveal or delete the password."""
    return templates.TemplateResponse(request, "reveal.html", {"token": token})


@app.post("/password/{token}", response_class=HTMLResponse)
def reveal_password(request: Request, token: str) -> HTMLResponse:
    """Show the password once and delete it."""
    password = consume_password(token)
    if password is None:
        return templates.TemplateResponse(
            request,
            "missing.html",
            status_code=status.HTTP_404_NOT_FOUND,
        )
    return templates.TemplateResponse(request, "password.html", {"password": password})
