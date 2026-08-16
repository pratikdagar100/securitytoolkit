import pytest

from security_toolkit.core.authorization import (
    AuthorizationContext, AuthorizationError, PASSIVE, ASSESSMENT, AUTHORIZED_LAB,
)


def test_passive_allows_recon_anywhere():
    ctx = AuthorizationContext(profile=PASSIVE)
    ctx.authorize("example.com", "recon", "passive")  # should not raise


def test_assessment_requires_scope_or_authorization():
    ctx = AuthorizationContext(profile=ASSESSMENT, scopes=[])
    with pytest.raises(AuthorizationError):
        ctx.authorize("example.com", "web", "assessment")
    ctx.authorized = True
    ctx.authorize("example.com", "web", "assessment")  # ok with explicit authorization


def test_assessment_in_scope_ok():
    ctx = AuthorizationContext(profile=ASSESSMENT, scopes=["example.com"])
    ctx.authorize("api.example.com", "web", "assessment")


def test_intrusive_needs_confirmation_and_scope():
    ctx = AuthorizationContext(profile=AUTHORIZED_LAB, scopes=["10.0.0.0/24"],
                               authorized=True, confirm=lambda p: False)
    with pytest.raises(AuthorizationError):
        ctx.authorize("10.0.0.5", "exploit", "intrusive")  # confirm denies
    ctx.confirm = lambda p: True
    ctx.authorize("10.0.0.5", "exploit", "intrusive")  # confirmed + in scope


def test_intrusive_blocked_when_profile_too_low():
    ctx = AuthorizationContext(profile=ASSESSMENT, scopes=["10.0.0.0/24"],
                               authorized=True, confirm=lambda p: True)
    with pytest.raises(AuthorizationError):
        ctx.authorize("10.0.0.5", "exploit", "intrusive")


def test_flag_cannot_bypass_scope_for_intrusive():
    # --authorized alone must not authorize an out-of-scope intrusive op.
    ctx = AuthorizationContext(profile=AUTHORIZED_LAB, scopes=["10.0.0.0/24"],
                               authorized=True, confirm=lambda p: True)
    with pytest.raises(AuthorizationError):
        ctx.authorize("192.168.1.1", "exploit", "intrusive")
