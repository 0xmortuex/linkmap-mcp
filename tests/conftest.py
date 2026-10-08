import os

import pytest

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def fx(*parts: str) -> str:
    return os.path.join(FIX, *parts)


@pytest.fixture
def anyio_backend():
    return "asyncio"
