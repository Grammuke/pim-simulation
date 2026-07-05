# Meridian General Hospital — PIM Activation Simulation

## What this is

A working simulation of Privileged Identity Management (PIM) — the model
where nobody holds admin rights by default, and every use of a privileged
role has to be requested, justified, and (for the highest-risk roles)
approved by someone else before it's granted.

This project models three roles for a fictional hospital IT environment
(Meridian General Hospital, the same organization used in my RBAC and
access-review projects):

- **Global Administrator** — 4-hour activation window, requires approval, requires MFA re-auth
- **Privileged Role Administrator** — 2-hour window, requires approval, requires MFA re-auth
- **EHR System Admin** — 8-hour window, MFA re-auth required, no approval needed

## Why this is a simulation and not a live Entra tenant build

Native PIM requires Microsoft Entra ID P2 licensing. The 30-day P2 trial
in my tenant required a payment method for identity verification that I
wasn't able to get accepted, and the Microsoft 365 Developer Program's
free E5 sandbox — which normally includes P2 — didn't qualify my account
either. Rather than fake screenshots of a tenant I don't have, I built
the actual decision logic that PIM enforces and ran it against realistic
scenarios, so the design can be inspected and tested directly instead of
just described.

The full policy specification — role configuration, approval routing,
activation windows, and the threat scenario behind each decision — is in
[`docs/design-and-threat-model.md`](docs/design-and-threat-model.md).

## What the simulation actually checks

Every activation request goes through the same sequence a real PIM
activation does:

1. Does this user hold an *eligible* assignment for this role at all?
   (Eligibility isn't access — it's the permission to request access.)
2. Is the justification long enough to mean something, not just a
   placeholder string?
3. Did the user pass a fresh MFA challenge specifically for this
   activation — not just at their original login?
4. Does this role require a second person to approve the request?
5. Once active, does the grant expire on its own without anyone having
   to remember to revoke it?

## Running it

```bash
python3 run_simulation.py
```

No dependencies beyond the Python standard library.

## What the demo walks through

- A legitimate Global Admin activation that gets approved and later
  auto-expires
- A request rejected for a lazy justification, before it ever reaches
  an approver
- A request rejected for failing MFA re-auth — the control that matters
  most if a session or token is ever stolen, since standing login alone
  isn't enough to elevate
- A lower-risk role (EHR System Admin) activating immediately without
  approval, since not every role justifies the same overhead
- A user with no PIM eligibility at all being blocked outright, which is
  the difference between PIM and just "MFA on the admin portal"

Every event — approved, denied, activated, expired — is written to an
audit log printed at the end of the run.

## Files

- `models.py` — role definitions, policy configuration, data structures
- `pim_engine.py` — the enforcement logic and audit logging
- `run_simulation.py` — runnable demo scenario
- `docs/design-and-threat-model.md` — full write-up of why each policy
  is configured the way it is
