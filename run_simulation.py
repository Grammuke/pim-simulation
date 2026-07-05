"""
Runnable demo: a day in the life of PIM at Meridian General Hospital.

Walks through five scenarios that show the policy engine actually doing
its job -- not just the happy path, but the denials too, since those are
the moments that matter most in an interview conversation.

Run with: python run_simulation.py
"""

from datetime import datetime, timedelta
from models import User, RoleName, EligibleAssignment
from pim_engine import PIMEngine

# --- Meridian General Hospital cast (consistent with Projects 3 & 4) ---

sarah = User("Sarah Okafor", "sarah.okafor@meridian.local", "IT Systems Administrator")
david = User("David Chen", "david.chen@meridian.local", "Senior IT Manager")  # approver
priya = User("Priya Nair", "priya.nair@meridian.local", "Clinical Systems Admin")
marcus = User("Marcus Webb", "marcus.webb@meridian.local", "Help Desk Technician")  # NOT eligible for anything

# --- Eligible assignments (who CAN request what -- not who already has it) ---

eligible_assignments = [
    EligibleAssignment(sarah, RoleName.GLOBAL_ADMIN, datetime.now() - timedelta(days=10), approver=david),
    EligibleAssignment(sarah, RoleName.PRIVILEGED_ROLE_ADMIN, datetime.now() - timedelta(days=10), approver=david),
    EligibleAssignment(priya, RoleName.EHR_SYSTEM_ADMIN, datetime.now() - timedelta(days=30)),
]

engine = PIMEngine(eligible_assignments)

print("=" * 70)
print("MERIDIAN GENERAL HOSPITAL -- PIM ACTIVATION SIMULATION")
print("=" * 70)

# --- Scenario 1: Legitimate Global Admin activation, properly approved ---
print("\n[Scenario 1] Sarah needs Global Admin to run a scheduled tenant migration task.")
req1 = engine.request_activation(
    user=sarah,
    role=RoleName.GLOBAL_ADMIN,
    justification="Running scheduled Q3 tenant configuration migration per change ticket CHG-1042.",
    mfa_reauth_passed=True,
)
print(f"  -> Status after request: {req1.status.value}")

print("  David (approver) reviews and approves the request.")
engine.approve(req1, approver=david, decision=True)
print(f"  -> Status after approval: {req1.status.value}, expires at {req1.expires_at.strftime('%H:%M:%S')}")

# --- Scenario 2: Weak justification gets auto-rejected before it ever reaches an approver ---
print("\n[Scenario 2] Sarah tries to activate Privileged Role Admin with a lazy justification.")
req2 = engine.request_activation(
    user=sarah,
    role=RoleName.PRIVILEGED_ROLE_ADMIN,
    justification="need it",
    mfa_reauth_passed=True,
)
print(f"  -> Status: {req2.status.value} (never reached David -- policy caught it first)")

# --- Scenario 3: MFA re-auth fails at the point of activation ---
print("\n[Scenario 3] Someone attempts to activate Sarah's Global Admin eligibility from a")
print("             session where the MFA challenge was not completed (e.g. hijacked browser session).")
req3 = engine.request_activation(
    user=sarah,
    role=RoleName.GLOBAL_ADMIN,
    justification="Continuing yesterday's migration task, needed a bit longer.",
    mfa_reauth_passed=False,
)
print(f"  -> Status: {req3.status.value}")
print("  This is the control that matters if a token or session is ever stolen:")
print("  standing login alone is not enough to elevate privilege.")

# --- Scenario 4: EHR System Admin activation, no approval needed, but MFA still required ---
print("\n[Scenario 4] Priya needs EHR System Admin to fix a broken record-access rule during her shift.")
req4 = engine.request_activation(
    user=priya,
    role=RoleName.EHR_SYSTEM_ADMIN,
    justification="Correcting misconfigured record access rule for Radiology department, ticket HD-3391.",
    mfa_reauth_passed=True,
)
print(f"  -> Status: {req4.status.value} (activated immediately -- no approval required for this role tier)")
print(f"  -> Expires at {req4.expires_at.strftime('%H:%M:%S')} ({req4.expires_at - req4.activated_at} window)")

# --- Scenario 5: A user with no eligibility at all tries their luck ---
print("\n[Scenario 5] Marcus, a help desk technician with no PIM eligibility, attempts to")
print("             activate Global Administrator directly.")
req5 = engine.request_activation(
    user=marcus,
    role=RoleName.GLOBAL_ADMIN,
    justification="I just need to check something quickly in the admin center.",
    mfa_reauth_passed=True,
)
print(f"  -> Status: {req5.status.value}")
print("  Eligibility has to exist before activation is even possible -- this is what")
print("  makes PIM different from just 'MFA on the admin portal.'")

# --- Force an expiry check to show the automatic sweep ---
print("\n[Time skip] Fast-forwarding past Sarah's 4-hour Global Admin window...")
future = datetime.now() + timedelta(hours=5)
engine.expire_overdue(as_of=future)
print(f"  -> Sarah's Scenario 1 grant status is now: {req1.status.value}")
print("  No one had to remember to revoke it. The access simply stopped existing.")

# --- Print the full audit trail ---
engine.audit_log.print_log()

print("\n" + "=" * 70)
print("Summary: 5 requests processed -- 1 clean activation, 1 policy rejection")
print("(weak justification), 1 MFA rejection, 1 no-approval-needed activation,")
print("1 rejected for lacking eligibility entirely. One grant auto-expired.")
print("=" * 70)
