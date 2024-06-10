"""Tests for asynchronous Python client for aioautomower.

Run tests with `poetry run pytest`
and to update snapshots `poetry run pytest --snapshot-update`
"""

from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

from aiohttp import ClientResponseError


def load_fixture(filename: str) -> str:
    """Load a fixture."""
    path = Path(__package__) / "fixtures" / filename
    return path.read_text(encoding="utf-8")


def mock_response(data: dict[str, Any], status: int = 200, json: bool = True):
    """Return aiohttp response json."""
    mock = AsyncMock()
    mock.return_value.status = status
    if json:
        mock.return_value.json = AsyncMock(return_value=data)

    if status // 100 in [4, 5]:
        mock.return_value.raise_for_status = Mock(
            side_effect=ClientResponseError(
                request_info=AsyncMock(), history=(), status=status, message="Error"
            )
        )
    return mock()
