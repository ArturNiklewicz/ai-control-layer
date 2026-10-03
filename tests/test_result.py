import asyncio

import pytest

from src.result import Err, Ok, attempt


def f(x):
    return Ok(x + 1) if x < 10 else Err("too big")


def g(x):
    return Ok(x * 2) if x % 2 else Err("even")


VALUES = [Ok(1), Ok(2), Ok(9), Ok(10), Err("e")]


@pytest.mark.parametrize("a", [1, 2, 9, 10])
def test_left_identity(a):
    assert Ok(a).bind(f) == f(a)


@pytest.mark.parametrize("m", VALUES)
def test_right_identity(m):
    assert m.bind(Ok) == m


@pytest.mark.parametrize("m", VALUES)
def test_associativity(m):
    assert m.bind(f).bind(g) == m.bind(lambda x: f(x).bind(g))


def test_map_transforms_success_only():
    assert Ok(2).map(lambda x: x + 1) == Ok(3)
    assert Err("e").map(lambda x: x + 1) == Err("e")
    assert Err("e").bind(f) == Err("e")


def test_attempt_maps_only_listed_exceptions():
    assert attempt(lambda: 1, (ValueError,), str) == Ok(1)
    assert attempt(lambda: int("x"), (ValueError,), lambda e: "bad") == Err("bad")


@pytest.mark.parametrize(
    "exc", [ZeroDivisionError("bug"), KeyError("bug"), asyncio.CancelledError()]
)
def test_attempt_lets_bugs_and_cancellation_propagate(exc):
    def boom():
        raise exc

    with pytest.raises(type(exc)):
        attempt(boom, (ValueError,), str)
