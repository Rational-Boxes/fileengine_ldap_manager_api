"""Auth-category audit emission for ldap_manager (usage_logging_and_auditing
§3/§5). Uses the shared ``AuditPublisher`` from the audit_service package.

In production the ``audit_service`` package is installed; for a sibling checkout
(dev) we fall back to ``../audit_service/src`` on the path — mirroring how the
other services reuse intra-repo code. Emission is gated on
``FILEENGINE_AUDIT_ENABLED`` and connects to the shared broker via the publisher's
``from_env()`` (``FILEENGINE_REDIS_*`` / ``FILEENGINE_AUDIT_STREAM``), NOT this
service's own ``REDIS_URL`` (which is only its token store).
"""
from __future__ import annotations

import logging
import os
import sys

log = logging.getLogger("ldap_manager.audit")

# This service's door identifier, recorded as source_iface on every entry.
IFACE = "ldapadmin"


def _import_publisher():
    try:
        from audit_service.publisher import AuditPublisher
        return AuditPublisher
    except ModuleNotFoundError:
        here = os.path.dirname(os.path.abspath(__file__))
        sibling = os.path.normpath(os.path.join(here, "..", "..", "..", "audit_service", "src"))
        if os.path.isdir(sibling) and sibling not in sys.path:
            sys.path.insert(0, sibling)
        from audit_service.publisher import AuditPublisher
        return AuditPublisher


class AuditEmitter:
    """Publishes ``auth``-category audit events, or is a no-op when disabled.

    ``emit()`` returns True when the entry was durably captured *or* auditing is
    off — so a fail-closed caller (password change / reset complete) can refuse
    the credential change on a False return without hard-coupling to whether
    auditing is configured.
    """

    def __init__(self, enabled: bool, *, iface: str = IFACE, publisher=None):
        self.iface = iface
        self._pub = publisher
        if publisher is None and enabled:
            try:
                self._pub = _import_publisher().from_env()
            except Exception:
                log.exception("audit publisher unavailable; auth auditing disabled")
                self._pub = None

    @property
    def enabled(self) -> bool:
        return self._pub is not None

    def emit(self, *, action: str, outcome: str, actor: str, **fields) -> bool:
        if self._pub is None:
            return True  # disabled -> never blocks the guarded operation
        try:
            return self._pub.publish(category="auth", action=action, outcome=outcome,
                                     actor=actor, source_iface=self.iface, **fields)
        except Exception:
            log.exception("audit emit failed for action=%s", action)
            return False
