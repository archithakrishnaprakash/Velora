import unittest

from velora.authz.identity import IdentityResolver, MissingCredentialError
from velora.authz.matrix import ResourceSpec, build_matrix, expectation_for
from velora.authz.runner import classify_observation, classify_outcome
from velora.core.http import HttpResponse
from velora.models.domain import Identity
from velora.models.enums import (
    AccessExpectation,
    AccessObservation,
    AuthzOutcome,
    IdentityRole,
)


def ident(name, role, secret_ref="", scheme=None):
    return Identity(name=name, role=role, secret_ref=secret_ref,
                    auth_scheme=scheme or ("none" if role == IdentityRole.ANONYMOUS else "bearer"))


def resp(status=200, body="", headers=None, ct="application/json", err=None):
    h = dict(headers or {})
    h.setdefault("Content-Type", ct)
    return HttpResponse(url="http://lab/r", final_url="http://lab/r", method="GET",
                        status_code=status, headers=h, content_type=ct, body=body,
                        response_size=len(body), elapsed_ms=1.0, error=err)


class TestIdentityResolver(unittest.TestCase):
    def test_anonymous_needs_no_credential(self):
        r = IdentityResolver(env={}).resolve(ident("anon", IdentityRole.ANONYMOUS))
        self.assertTrue(r.resolved)
        self.assertEqual(r.headers, {})
        self.assertTrue(r.is_anonymous)

    def test_bearer_header_built_from_env(self):
        r = IdentityResolver(env={"TOK": "abc123"}).resolve(
            ident("alice", IdentityRole.USER_A, "TOK"))
        self.assertEqual(r.headers, {"Authorization": "Bearer abc123"})
        self.assertTrue(r.resolved)

    def test_missing_credential_degrades_but_is_marked(self):
        r = IdentityResolver(env={}).resolve(ident("alice", IdentityRole.USER_A, "TOK"))
        self.assertFalse(r.resolved)
        self.assertEqual(r.headers, {})
        self.assertIn("TOK", r.reason)

    def test_strict_mode_raises_on_missing_credential(self):
        with self.assertRaises(MissingCredentialError):
            IdentityResolver(env={}).resolve(ident("a", IdentityRole.USER_A, "TOK"), strict=True)

    def test_safe_summary_never_contains_the_secret(self):
        r = IdentityResolver(env={"TOK": "super-secret-value"}).resolve(
            ident("alice", IdentityRole.USER_A, "TOK"))
        blob = str(r.safe_summary())
        self.assertNotIn("super-secret-value", blob)
        self.assertIn("TOK", blob)          # the reference name is fine
        self.assertIn("Authorization", blob)  # header NAME is fine

    def test_available_reflects_environment(self):
        resolver = IdentityResolver(env={"TOK": "x"})
        self.assertTrue(resolver.available(ident("a", IdentityRole.USER_A, "TOK")))
        self.assertFalse(resolver.available(ident("b", IdentityRole.USER_B, "OTHER")))
        self.assertTrue(resolver.available(ident("anon", IdentityRole.ANONYMOUS)))


class TestMatrix(unittest.TestCase):
    def test_owner_is_allowed_and_peer_is_denied(self):
        alice, bob = ident("alice", IdentityRole.USER_A), ident("bob", IdentityRole.USER_B)
        res = ResourceSpec(url="http://lab/o/1", owner="alice")
        self.assertEqual(expectation_for(alice, res)[0], AccessExpectation.ALLOW)
        self.assertEqual(expectation_for(bob, res)[0], AccessExpectation.DENY)

    def test_anonymous_denied_on_owned_resource(self):
        anon = ident("anon", IdentityRole.ANONYMOUS)
        self.assertEqual(
            expectation_for(anon, ResourceSpec(url="u", owner="alice"))[0],
            AccessExpectation.DENY)

    def test_admin_on_other_users_resource_is_unknown_not_deny(self):
        """An admin may legitimately read another user's record — don't assume a weakness."""
        admin = ident("admin", IdentityRole.ADMIN)
        self.assertEqual(
            expectation_for(admin, ResourceSpec(url="u", owner="alice"))[0],
            AccessExpectation.UNKNOWN)

    def test_required_role_governs_vertical_expectation(self):
        res = ResourceSpec(url="u", requires_role=IdentityRole.ADMIN)
        self.assertEqual(expectation_for(ident("a", IdentityRole.USER_A), res)[0],
                         AccessExpectation.DENY)
        self.assertEqual(expectation_for(ident("ad", IdentityRole.ADMIN), res)[0],
                         AccessExpectation.ALLOW)

    def test_explicit_expectation_overrides_derivation(self):
        res = ResourceSpec(url="u", owner="alice", expectations={"bob": "ALLOW"})
        self.assertEqual(expectation_for(ident("bob", IdentityRole.USER_B), res)[0],
                         AccessExpectation.ALLOW)

    def test_undeclared_resource_yields_unknown(self):
        self.assertEqual(expectation_for(ident("a", IdentityRole.USER_A),
                                         ResourceSpec(url="u"))[0], AccessExpectation.UNKNOWN)

    def test_matrix_is_full_cross_product(self):
        ids = [ident("a", IdentityRole.USER_A), ident("b", IdentityRole.USER_B)]
        res = [ResourceSpec(url="1"), ResourceSpec(url="2"), ResourceSpec(url="3")]
        self.assertEqual(len(build_matrix(ids, res)), 6)


class TestObservationClassification(unittest.TestCase):
    def test_401_403_are_denied(self):
        self.assertEqual(classify_observation(resp(401))[0], AccessObservation.DENIED)
        self.assertEqual(classify_observation(resp(403))[0], AccessObservation.DENIED)

    def test_200_with_resource_is_granted(self):
        self.assertEqual(classify_observation(resp(200, '{"order":1}'))[0],
                         AccessObservation.GRANTED)

    def test_200_login_page_is_denied_not_granted(self):
        body = '<html><form action="/login" class="signin">please log in</form></html>'
        self.assertEqual(classify_observation(resp(200, body, ct="text/html"))[0],
                         AccessObservation.DENIED)

    def test_redirect_to_login_is_denied(self):
        self.assertEqual(
            classify_observation(resp(302, headers={"Location": "/login?next=/x"}))[0],
            AccessObservation.DENIED)

    def test_404_is_inconclusive_not_granted(self):
        self.assertEqual(classify_observation(resp(404))[0], AccessObservation.INCONCLUSIVE)

    def test_server_error_is_inconclusive(self):
        self.assertEqual(classify_observation(resp(500))[0], AccessObservation.INCONCLUSIVE)

    def test_transport_error_is_error(self):
        self.assertEqual(classify_observation(resp(0, err="timeout"))[0], AccessObservation.ERROR)


class TestOutcomeClassification(unittest.TestCase):
    def _case(self, identity, resource, expected):
        from velora.authz.matrix import AuthzCase
        return AuthzCase(identity=identity, resource=resource, expected=expected)

    def test_anonymous_granted_where_denied_is_unauthenticated_access(self):
        case = self._case(ident("anon", IdentityRole.ANONYMOUS),
                          ResourceSpec(url="u", owner="alice"), AccessExpectation.DENY)
        self.assertEqual(classify_outcome(case, AccessObservation.GRANTED)[0],
                         AuthzOutcome.UNAUTHENTICATED_ACCESS)

    def test_peer_granted_where_denied_is_horizontal(self):
        case = self._case(ident("bob", IdentityRole.USER_B),
                          ResourceSpec(url="u", owner="alice"), AccessExpectation.DENY)
        self.assertEqual(classify_outcome(case, AccessObservation.GRANTED)[0],
                         AuthzOutcome.HORIZONTAL_AUTHORIZATION_WEAKNESS)

    def test_low_role_granted_on_privileged_resource_is_vertical(self):
        case = self._case(ident("alice", IdentityRole.USER_A),
                          ResourceSpec(url="u", requires_role=IdentityRole.ADMIN),
                          AccessExpectation.DENY)
        self.assertEqual(classify_outcome(case, AccessObservation.GRANTED)[0],
                         AuthzOutcome.VERTICAL_AUTHORIZATION_WEAKNESS)

    def test_denied_as_expected_is_not_a_weakness(self):
        case = self._case(ident("bob", IdentityRole.USER_B),
                          ResourceSpec(url="u", owner="alice"), AccessExpectation.DENY)
        outcome, _ = classify_outcome(case, AccessObservation.DENIED)
        self.assertEqual(outcome, AuthzOutcome.AS_EXPECTED)
        self.assertFalse(outcome.is_weakness)

    def test_unknown_expectation_never_produces_a_weakness(self):
        case = self._case(ident("a", IdentityRole.USER_A), ResourceSpec(url="u"),
                          AccessExpectation.UNKNOWN)
        self.assertEqual(classify_outcome(case, AccessObservation.GRANTED)[0],
                         AuthzOutcome.INCONCLUSIVE)

    def test_allow_but_denied_is_inconclusive_not_a_weakness(self):
        """A broken credential must not be reported as a security weakness."""
        case = self._case(ident("a", IdentityRole.USER_A),
                          ResourceSpec(url="u", owner="a"), AccessExpectation.ALLOW)
        outcome, reason = classify_outcome(case, AccessObservation.DENIED)
        self.assertEqual(outcome, AuthzOutcome.INCONCLUSIVE)
        self.assertIn("not treated as a security weakness", reason)

    def test_inconclusive_observation_never_becomes_a_weakness(self):
        case = self._case(ident("bob", IdentityRole.USER_B),
                          ResourceSpec(url="u", owner="alice"), AccessExpectation.DENY)
        self.assertEqual(classify_outcome(case, AccessObservation.INCONCLUSIVE)[0],
                         AuthzOutcome.INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()
