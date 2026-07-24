# Copyright (C) 2026 James Hickman
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Real client-IP resolution behind a reverse proxy (PROPOSAL §3), mirroring the
C++ bridges' ``client_ip.h`` so every tier derives the SAME client IP.

Configure ``FILEENGINE_TRUSTED_PROXIES`` (comma-separated IPs/CIDRs of the reverse
proxy). When set, X-Forwarded-For is credible only if the immediate peer is a
trusted proxy, and the client is the right-most XFF hop that is NOT itself a
trusted proxy. When unset (development), the first XFF hop is trusted for
convenience — do not run that way in production.
"""
from __future__ import annotations

import ipaddress
import os

from fastapi import Request


def parse_trusted(raw: str) -> list:
    nets = []
    for c in (raw or "").split(","):
        c = c.strip()
        if not c:
            continue
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


def _is_trusted(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def resolve_client_ip(peer: str, xff_header: str, trusted=None) -> str:
    nets = parse_trusted(os.environ.get("FILEENGINE_TRUSTED_PROXIES", "")) if trusted is None else trusted
    hops = [h.strip() for h in (xff_header or "").split(",") if h.strip()]
    if not nets:  # dev: trust the first XFF hop, else the peer
        return hops[0] if hops else (peer or "")
    if not _is_trusted(peer or "", nets):
        return peer or ""
    if not hops:
        return peer or ""
    for h in reversed(hops):
        if not _is_trusted(h, nets):
            return h
    return peer or ""


def client_ip(request: Request) -> str:
    """Real client IP behind the nginx /ldapadmin proxy — trusted-proxy aware
    (FILEENGINE_TRUSTED_PROXIES). Falls back to X-Real-IP, then the socket peer."""
    peer = request.client.host if request.client else ""
    ip = resolve_client_ip(peer, request.headers.get("x-forwarded-for", ""))
    return ip or request.headers.get("x-real-ip") or peer or "unknown"
