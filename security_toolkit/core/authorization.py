"""Authorization / safety architecture.

Three execution profiles gate what a module may do:

  PASSIVE        - information gathering only, no intrusive requests.
  ASSESSMENT     - controlled, rate-limited, non-destructive checks.
  AUTHORIZED_LAB - intentionally vulnerable machines / controlled labs;
                   requires explicit target, operation and confirmation.

The authorization layer cannot be bypassed by a hidden flag: intrusive
operations require both an in-scope target *and* an explicit confirmation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from security_toolkit.core import target_validator

PASSIVE = "PASSIVE"
ASSESSMENT = "ASSESSMENT"
AUTHORIZED_LAB = "AUTHORIZED_LAB"
PROFILES = [PASSIVE, ASSESSMENT, AUTHORIZED_LAB]

# Minimum profile required to perform an operation class.
OPERATION_MIN_PROFILE = {
    "passive": PASSIVE,
    "assessment": ASSESSMENT,
    "intrusive": AUTHORIZED_LAB,
}

_PROFILE_RANK = {PASSIVE: 0, ASSESSMENT: 1, AUTHORIZED_LAB: 2}


class AuthorizationError(Exception):
    """Raised when an operation is not permitted under the current context."""


@dataclass
class AuthorizationContext:
    profile: str = PASSIVE
    case_id: str = ""
    scopes: List[str] = field(default_factory=list)
    authorized: bool = False          # user asserted authorization (e.g. --authorized)
    user: str = "local"
    # confirm(prompt) -> bool. Defaults to deny so non-interactive runs are safe.
    confirm: Callable[[str], bool] = field(default=lambda prompt: False)

    def normalize(self) -> None:
        self.profile = (self.profile or PASSIVE).upper()
        if self.profile not in PROFILES:
            self.profile = PASSIVE

    def permits(self, operation_class: str) -> bool:
        self.normalize()
        needed = OPERATION_MIN_PROFILE.get(operation_class, AUTHORIZED_LAB)
        return _PROFILE_RANK[self.profile] >= _PROFILE_RANK[needed]

    def authorize(self, target: str, operation: str, operation_class: str = "assessment") -> None:
        """Validate scope + profile + confirmation for one operation.

        Raises ``AuthorizationError`` if the operation must not proceed.
        """
        self.normalize()

        result = target_validator.classify(target)
        if not result.valid:
            raise AuthorizationError(f"Invalid target '{target}': {result.reason}")

        if not self.permits(operation_class):
            raise AuthorizationError(
                f"Operation '{operation}' ({operation_class}) requires at least "
                f"profile {OPERATION_MIN_PROFILE.get(operation_class)}; current "
                f"profile is {self.profile}."
            )

        # Passive operations against any classified target are always allowed.
        if operation_class == "passive":
            return

        scoped = target_validator.in_scope(target, self.scopes)

        if operation_class == "intrusive":
            # Intrusive work demands authorization AND scope AND explicit confirm.
            if not self.authorized:
                raise AuthorizationError(
                    "Intrusive operation requires explicit authorization "
                    "(--authorized / confirmed lab authorization)."
                )
            if not scoped:
                raise AuthorizationError(
                    f"Target '{target}' is not within the authorized scope "
                    f"{self.scopes or '[none defined]'}."
                )
            prompt = (
                f"AUTHORIZED SECURITY TEST\n"
                f"  Case:      {self.case_id or '(none)'}\n"
                f"  Target:    {target}\n"
                f"  Operation: {operation}\n"
                f"  Scope:     {', '.join(self.scopes) or '(none)'}\n"
                f"Proceed?"
            )
            if not self.confirm(prompt):
                raise AuthorizationError("Operation not confirmed by operator.")
            return

        # assessment class: require in-scope OR an explicit authorization flag.
        if not (scoped or self.authorized):
            raise AuthorizationError(
                f"Target '{target}' is not in authorized scope and no explicit "
                f"authorization was provided for assessment operations."
            )
