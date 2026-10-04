#!/usr/bin/env python3
"""version.py — the released product's version, which is NOT the bus protocol's version.

`agent_bus.PROTOCOL_VERSION` describes the wire: peers exchange it (see `bus_ssh_exchange`), and the frozen
contract in `docs/AGENT_BUS_SCHEMA.md` is written against it. `RELEASE_VERSION` describes the archive we hand
to a buyer — packaging, installer, evidence envelope, release gate.

They started out as one number because the first release changed both at once. They are not the same claim: a
patch release that fixes the release machinery must not tell every peer on the wire that the protocol moved.
So the release version moves on its own, and the two are held together by the rule below instead of by being
the same string — a patch release keeps the protocol's MAJOR.MINOR, and anything wider is a protocol change
that has to be made deliberately in `agent_bus.py`.
"""
from __future__ import annotations

RELEASE_VERSION = "1.5.7"


def same_line(release: str, protocol: str) -> bool:
    """True if `release` is a patch release of `protocol`'s line — 1.5.3 belongs to protocol 1.5.0, 1.6.0 does not."""
    return release.split(".")[:2] == protocol.split(".")[:2]
