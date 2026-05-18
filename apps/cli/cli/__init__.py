"""Virgil CLI.

Thin terminal client for Virgil — the security audit platform. Submits
scans, streams audit progress, prints findings, fetches reports — talks
to a running API instance (default `http://localhost:8000`). The CLI
never runs scanners itself; that work belongs in the sandboxed worker.

Distribution: `pip install virgil` (or via `pipx`).
"""
__version__ = "0.1.0"
