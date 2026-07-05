"""
Data models for the Meridian General Hospital PIM simulation.

This models the core PIM lifecycle: a user is made ELIGIBLE for a role,
then must ACTIVATE that role (with justification, MFA re-auth, and
sometimes approval) before they can actually use it. Every activation
is time-bound and gets logged.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import uuid


class RoleName(str, Enum):
    GLOBAL_ADMIN = "Global Administrator"
    PRIVILEGED_ROLE_ADMIN = "Privileged Role Administrator"
    EHR_SYSTEM_ADMIN = "EHR System Admin"


class RequestStatus(str, Enum):
    PENDING_APPROVAL = "Pending Approval"
    APPROVED = "Approved"
    DENIED = "Denied"
    ACTIVE = "Active"
    EXPIRED = "Expired"
    REJECTED_MFA_FAILED = "Rejected (MFA re-auth failed)"


@dataclass(frozen=True)
class RolePolicy:
    """
    The PIM configuration for a single role. This is the enforcement
    layer -- every activation request gets checked against these rules.
    """
    name: RoleName
    max_activation_hours: int
    requires_approval: bool
    requires_mfa_reauth: bool
    min_justification_chars: int
    access_review_interval_days: int


# The three roles in scope for this project, configured per the design doc.
ROLE_POLICIES = {
    RoleName.GLOBAL_ADMIN: RolePolicy(
        name=RoleName.GLOBAL_ADMIN,
        max_activation_hours=4,
        requires_approval=True,
        requires_mfa_reauth=True,
        min_justification_chars=20,
        access_review_interval_days=90,
    ),
    RoleName.PRIVILEGED_ROLE_ADMIN: RolePolicy(
        name=RoleName.PRIVILEGED_ROLE_ADMIN,
        max_activation_hours=2,
        requires_approval=True,
        requires_mfa_reauth=True,
        min_justification_chars=20,
        access_review_interval_days=90,
    ),
    RoleName.EHR_SYSTEM_ADMIN: RolePolicy(
        name=RoleName.EHR_SYSTEM_ADMIN,
        max_activation_hours=8,
        requires_approval=False,
        requires_mfa_reauth=True,
        min_justification_chars=20,
        access_review_interval_days=60,
    ),
}


@dataclass
class User:
    display_name: str
    upn: str
    job_title: str


@dataclass
class EligibleAssignment:
    """
    A user who CAN activate a role, but does not hold it by default.
    This is the whole point of PIM -- eligibility is not access.
    """
    user: User
    role: RoleName
    assigned_on: datetime
    approver: User | None = None  # who can approve activations for this role, if required


@dataclass
class ActivationRequest:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    user: User = None
    role: RoleName = None
    justification: str = ""
    requested_at: datetime = field(default_factory=datetime.now)
    mfa_reauth_passed: bool = False
    status: RequestStatus = RequestStatus.PENDING_APPROVAL
    approved_by: User | None = None
    activated_at: datetime | None = None
    expires_at: datetime | None = None
