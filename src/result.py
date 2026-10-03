"""Result monad: Ok | Err with map/bind for composition (pattern from multimodal-rag).

map  = transform a success value (f returns a plain value).
bind = chain a step that can itself fail (f returns a Result); never map such f, or Results nest.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Generic, TypeVar

# explicit covariance: Err[A] must be usable as Result[T, A | B] when steps with
# different error types compose. PEP 695 inference makes frozen dataclasses invariant
# (the synthesized __replace__ takes the field as a parameter).
T_co = TypeVar("T_co", covariant=True)
E_co = TypeVar("E_co", covariant=True)


@dataclass(frozen=True, slots=True)
class Ok(Generic[T_co]):
    value: T_co

    def map[U](self, f: Callable[[T_co], U]) -> "Ok[U]":
        return Ok(f(self.value))

    def bind[U, E](self, f: "Callable[[T_co], Result[U, E]]") -> "Result[U, E]":
        return f(self.value)


@dataclass(frozen=True, slots=True)
class Err(Generic[E_co]):
    error: E_co

    def map(self, _f: Callable) -> "Err[E_co]":
        return self

    def bind(self, _f: Callable) -> "Err[E_co]":
        return self


type Result[T, E] = Ok[T] | Err[E]


def attempt[T, E](
    f: Callable[[], T],
    catch: tuple[type[Exception], ...],
    to_err: Callable[[Exception], E],
) -> Result[T, E]:
    """Lift a raising call into a Result at an I/O boundary.

    Only the expected exceptions in `catch` become Err (mapped to typed data by `to_err`);
    programming errors and cancellation propagate.
    """
    try:
        return Ok(f())
    except catch as e:
        return Err(to_err(e))
