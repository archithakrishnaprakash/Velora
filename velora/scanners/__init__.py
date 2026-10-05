"""Scanner framework and the built-in security checks.

Importing this package registers all built-in checks with the global ``registry``.
"""
from .base import (
    CheckOutput,
    CheckRegistry,
    EvidenceItem,
    ScanContext,
    SecurityCheck,
    register,
    registry,
)

# Import check modules for their registration side effects.
from .headers import check as _headers  # noqa: F401,E402
from .cookies import check as _cookies  # noqa: F401,E402
from .tls import check as _tls  # noqa: F401,E402
from .information_disclosure import check as _infodisc  # noqa: F401,E402
from .configuration import check as _config  # noqa: F401,E402
from .authentication import check as _authn  # noqa: F401,E402
from .authorization import check as _authz  # noqa: F401,E402
from .input_validation import check as _input  # noqa: F401,E402

from .runner import ScanRunner  # noqa: E402

__all__ = [
    "SecurityCheck",
    "CheckOutput",
    "EvidenceItem",
    "ScanContext",
    "CheckRegistry",
    "registry",
    "register",
    "ScanRunner",
]
