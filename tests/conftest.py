"""Shared test configuration."""

from __future__ import annotations


def pytest_addoption(parser):
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="run tests that hit external APIs (crt.sh)",
    )
