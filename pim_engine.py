"""
The enforcement engine. This is where a request actually gets checked
against the role's policy -- justification length, MFA re-auth, approval
requirement -- and where every decision gets written to the audit log.

Nothing here reaches out to a real Entra tenant. It's a stand-in for what
Entra ID P2 PIM would enforce natively, built so the logic can be read,
tested, and demonstrated without a live P2 license.
"""

from datetime import datetime, timedelta
from models import ROLE_POLICIES, ActivationRequest, RequestStatus, EligibleAssignment


class PolicyViolation(Exception):
    """Raised when a request doesn't meet the role's PIM policy."""
    pass


class AuditLog:
    def __init__(self):
        self.entries: list[dict] = []

    def record(self, event: str, request: ActivationRequest, detail: str = ""):
        self.entries.append({
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "event": event,
            "request_id": request.id,
            "user": request.user.display_name,
            "role": request.role.value,
            "status": request.status.value,
            "detail": detail,
        })

    def print_log(self):
        print("\n=== PIM AUDIT LOG ===")
        for entry in self.entries:
            print(f"[{entry['timestamp']}] {entry['event']:<20} "
                  f"user={entry['user']:<18} role={entry['role']:<28} "
                  f"status={entry['status']:<28} {entry['detail']}")


class PIMEngine:
    def __init__(self, eligible_assignments: list[EligibleAssignment]):
        self.eligible_assignments = eligible_assignments
        self.audit_log = AuditLog()
        self.requests: list[ActivationRequest] = []

    def _find_eligibility(self, user, role) -> EligibleAssignment | None:
        for ea in self.eligible_assignments:
            if ea.user.upn == user.upn and ea.role == role:
                return ea
        return None

    def request_activation(self, user, role, justification: str, mfa_reauth_passed: bool) -> ActivationRequest:
        """
        A user attempts to activate a role they're eligible for.
        This is the entry point -- every check below mirrors a real
        Entra PIM activation flow.
        """
        req = ActivationRequest(
            user=user,
            role=role,
            justification=justification,
            mfa_reauth_passed=mfa_reauth_passed,
        )
        self.requests.append(req)
        policy = ROLE_POLICIES[role]

        # Check 1: is this user even eligible for this role at all?
        eligibility = self._find_eligibility(user, role)
        if not eligibility:
            req.status = RequestStatus.DENIED
            self.audit_log.record("ACTIVATION_DENIED", req, "No eligible assignment found for this user/role")
            return req

        # Check 2: justification long enough to mean something
        if len(justification.strip()) < policy.min_justification_chars:
            req.status = RequestStatus.DENIED
            self.audit_log.record(
                "ACTIVATION_DENIED", req,
                f"Justification too short (min {policy.min_justification_chars} chars)"
            )
            return req

        # Check 3: MFA re-auth, required at activation time, not just at login
        if policy.requires_mfa_reauth and not mfa_reauth_passed:
            req.status = RequestStatus.REJECTED_MFA_FAILED
            self.audit_log.record("ACTIVATION_DENIED", req, "MFA re-authentication failed or not provided")
            return req

        # Check 4: does this role require a second person's approval?
        if policy.requires_approval:
            req.status = RequestStatus.PENDING_APPROVAL
            self.audit_log.record(
                "APPROVAL_REQUESTED", req,
                f"Awaiting approval from {eligibility.approver.display_name if eligibility.approver else 'assigned approver'}"
            )
            return req

        # No approval needed -- activate immediately
        self._activate(req, policy)
        return req

    def approve(self, request: ActivationRequest, approver, decision: bool):
        """An approver acts on a pending request."""
        if request.status != RequestStatus.PENDING_APPROVAL:
            raise PolicyViolation(f"Request {request.id} is not awaiting approval (status: {request.status.value})")

        policy = ROLE_POLICIES[request.role]
        request.approved_by = approver

        if decision:
            self.audit_log.record("APPROVED", request, f"Approved by {approver.display_name}")
            self._activate(request, policy)
        else:
            request.status = RequestStatus.DENIED
            self.audit_log.record("DENIED", request, f"Denied by {approver.display_name}")

    def _activate(self, request: ActivationRequest, policy):
        request.status = RequestStatus.ACTIVE
        request.activated_at = datetime.now()
        request.expires_at = request.activated_at + timedelta(hours=policy.max_activation_hours)
        self.audit_log.record(
            "ACTIVATED", request,
            f"Active until {request.expires_at.isoformat(timespec='seconds')} "
            f"({policy.max_activation_hours}h window)"
        )

    def expire_overdue(self, as_of: datetime | None = None):
        """
        Sweep for any active grants past their expiry. In real Entra ID PIM
        this happens automatically and silently -- no standing access survives
        the activation window, regardless of whether anyone remembers to revoke it.
        """
        as_of = as_of or datetime.now()
        for req in self.requests:
            if req.status == RequestStatus.ACTIVE and req.expires_at and as_of >= req.expires_at:
                req.status = RequestStatus.EXPIRED
                self.audit_log.record("EXPIRED", req, "Activation window closed automatically")
