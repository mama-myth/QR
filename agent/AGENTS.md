# Project Agent Contract — Peek-in QR

Read `security/SECURITY_GATES.md` before editing files, and read the source proposal (`proposal/Peek-in_QR_Project_Proposal_Synopsis..pdf` / attached package) and requirements baseline before implementing.

## Operating Rules
- High reasoning effort.
- Work continuously on local, reversible, in-scope tasks.
- Stop at security, money, external-effects, data-loss, or guardrail-change gates.
- Fresh consent required before git commit, push, PR creation, or live deployment.
- Never claim `VERIFIED` for weak evidence, never auto-open QR targets, and never log or upload raw QR contents.
- `ML unavailable` does not block deterministic offline MVP and may not be disguised as working ML.
- Backend unavailable must not block scanner.
- Every milestone needs an executed test command and result recorded in `docs/STATUS.md`.
- Approval needed before dependency additions, changing Android permissions, changing guardrails, calling external endpoints, committing/pushing, deploying, and any irreversible operation.
