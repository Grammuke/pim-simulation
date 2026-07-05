# PIM Design & Threat Model — Meridian General Hospital

## The problem

Under a standard setup, Meridian's IT admins hold roles like Global
Administrator permanently. There's no expiration, no re-authentication
at the point of use, and no second person involved in deciding when
that access actually gets exercised. If one admin's credentials are
phished, the attacker doesn't need to escalate privilege — they already
have it, and they have it for as long as the account exists.

Privileged Identity Management changes the default. Nobody holds a
sensitive role outright. They're made *eligible* for it, and every time
they actually need to use it, they have to request activation, justify
why, and in some cases wait for someone else to approve it. Access is
time-bound and closes itself out automatically.

## Roles in scope

I scoped this to three roles rather than trying to PIM-manage
everything in the tenant — in a real deployment you'd expand outward
from here, but these three cover the highest-risk cases and give a
clear before/after story:

| Role | Why it's in scope |
|---|---|
| Global Administrator | The most powerful role in the tenant. Full stop. |
| Privileged Role Administrator | Can grant *other* people admin roles — nearly as dangerous as Global Admin because it compounds. |
| EHR System Admin (custom role) | Ties to the RBAC work from Project 3 (`EHR.Write.OwnPatients`). Sensitive because it touches patient data directly, which matters under HIPAA. |

## Configuration and the reasoning behind it

### Global Administrator
- **Eligible, not standing** — no one holds this permanently.
- **4-hour activation window** — long enough to finish a real admin
  task, short enough that a compromised session doesn't stay dangerous
  indefinitely.
- **Requires approval** from a second admin before it activates.
- **Requires MFA re-authentication** at the moment of activation, not
  just at original sign-in.
- **Justification required**, minimum 20 characters — long enough that
  someone has to actually say what they're doing, not just type "need
  it."
- **Access review every 90 days** — someone eligible for a migration
  project six months ago may not need that eligibility anymore. Without
  a recurring review, unused eligibility just sits there as risk nobody
  notices.

**Threat scenario:** An admin's credentials get phished. Under a
standing-access model, the attacker has full tenant control the moment
they authenticate. Under PIM, that same phished credential gets the
attacker nothing on its own — actually elevating to Global Admin
requires a fresh MFA challenge they don't have, and a second admin has
to approve the request, which generates a visible event even if it's
never approved.

### Privileged Role Administrator
- Same approval and MFA requirements as Global Admin.
- **2-hour window, shorter than Global Admin** — this role can be used
  to grant *other* people privileged roles, so its own activation
  window should be tighter than the role it's one step removed from
  controlling.

**Threat scenario:** If this role were left as standing access, an
attacker who compromised it wouldn't need Global Admin directly — they
could just grant themselves or another account whatever role they
wanted. Restricting the window tightly limits how long that
grant-other-people's-access capability is actually live.

### EHR System Admin
- **8-hour window** — matches a full shift, since clinical/IT staff
  supporting the EHR may genuinely need access for a sustained period,
  not just a quick task.
- **MFA re-authentication required.**
- **No approval workflow.** This is a deliberate, lower-overhead choice:
  Global Admin and Privileged Role Administrator can compound (they can
  be used to grant more access to more people). EHR System Admin can't
  — its blast radius is contained to the EHR system itself. Requiring a
  second person to approve every EHR access request would slow down
  legitimate clinical support work without a proportionate security
  gain.
- **Access review every 60 days**, tighter than the 90-day cycle for the
  admin roles, because this role touches patient data and HIPAA's
  expectations around access oversight for PHI-adjacent systems are
  stricter than for general IT administration.

**Threat scenario:** A compromised or misused EHR System Admin
credential could expose patient records. The MFA re-auth requirement
still blocks a stolen session token from silently escalating, and the
shorter access review cycle means unused eligibility gets caught and
pulled faster than it would for the admin-tier roles.

## Why justification length is enforced at all

A one-word justification like "needed" gives you nothing to audit later.
Requiring a minimum length doesn't stop a determined bad actor from
typing filler text, but it does two things that matter in practice:
it creates a real audit trail for legitimate use (so a security review
six months later can actually tell what an activation was for), and it
adds enough friction that casual, unnecessary activations — the kind
that happen just because someone doesn't want to bother requesting
narrower access — become less likely.

## What "eligible but not activated" actually prevents

The single biggest shift PIM makes isn't the approval workflow or the
MFA re-auth — it's this: **most of the time, nobody has admin rights at
all.** An attacker who compromises an account with PIM eligibility (but
no active role) has compromised an account that currently does nothing
special. They'd have to trigger an activation to get anywhere, and that
activation is exactly the kind of event that shows up in an audit log
and, for the highest-risk roles, requires another human to say yes.

## Limitation

This project was fully designed and specified as above, but implemented
as a working simulation rather than a live Entra ID tenant configuration.
Microsoft Entra ID P2 — required for native PIM — needs either a paid
trial with payment verification or a Microsoft 365 Developer Program
sandbox, and neither route was accessible in this environment. The
simulation (`run_simulation.py` in the repo root) implements the actual
enforcement logic described above — eligibility checks, justification
validation, MFA re-auth gating, approval routing, and automatic
expiry — and runs it against realistic Meridian scenarios so the design
can be verified directly rather than taken on faith.
