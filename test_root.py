import pytest
from root import solve_roots
import math

def test_quadratic_roots():
    result = solve_roots("x^2 - 4")
    assert result["success"]
    roots = result["roots"]
    assert sorted(round(r, 5) for r in roots) == [-2.0, 2.0]

def test_cubic_roots():
    result = solve_roots("x^3 - 6*x^2 + 11*x - 6")
    assert result["success"]
    assert sorted(round(r, 5) for r in result["roots"]) == [1.0, 2.0, 3.0]


def test_quad_root():
    result = solve_roots("x^4 + 2*x^3 - 6*x^2 - 6*x + 9")
    assert result["success"]

    expected_roots = sorted([-3.0, -math.sqrt(3), 1.0, math.sqrt(3)])
    actual_roots = sorted(result["roots"])

    assert len(actual_roots) == len(expected_roots)

    for actual, expected in zip(actual_roots, expected_roots):
        assert actual == pytest.approx(expected, abs=1e-4)

def test_single_root():
    result = solve_roots("x")
    assert result["success"]
    assert len(result["roots"]) == 1
    assert abs(result["roots"][0]) < 1e-5

def test_invalid_expression():
    result = solve_roots("???")
    assert not result["success"]

def test_constant_expression():
    result = solve_roots("5")
    assert not result["success"]

def test_no_variable():
    result = solve_roots("2 + 3")
    assert not result["success"]
#Add more if you want
    