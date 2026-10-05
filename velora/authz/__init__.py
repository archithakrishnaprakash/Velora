"""Multi-identity authorization testing.

Builds a controlled matrix of *identity × resource* requests and compares what each
identity is **expected** to be able to reach against what it **actually** reached.

Safety properties:

* Credentials are never stored, logged, or reported. An ``Identity`` holds only a
  ``secret_ref`` — the *name* of an environment variable — and the value is read at
  request time and discarded.
* Every request goes through the scope-gated HTTP client.
* Nothing here attempts privilege escalation or exploitation; it issues ordinary
  requests as configured identities and records the responses.
* Outcomes are created as ``Potential`` findings requiring human validation. The
  framework never self-confirms an authorization weakness.
"""
from .identity import IdentityResolver, ResolvedIdentity
from .matrix import AuthzCase, AuthzMatrix, ResourceSpec, build_matrix
from .runner import AuthzRunner, AuthzTestResult
from .service import AuthorizationTestingService

__all__ = [
    "IdentityResolver",
    "ResolvedIdentity",
    "ResourceSpec",
    "AuthzCase",
    "AuthzMatrix",
    "build_matrix",
    "AuthzRunner",
    "AuthzTestResult",
    "AuthorizationTestingService",
]
