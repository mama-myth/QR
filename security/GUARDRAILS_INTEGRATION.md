# Guardrails Integration and Third-Party Adaptation Decision

## Guardrail Template Assessment
- Upstream reference template: `buddhika886/ai-dev-guardrails`, pinned reference commit `25d4a16f814a4b761d4bc66aff4a9e2f8a7afd7e`.
- Target: Pre-release Claude Code / TypeScript template.
- Decision: **ADAPT, NOT BLINDLY IMPORT.** Third-party scripts are not blindly executed. Rules are adapted for Flutter/Dart and Python/FastAPI stacks.
- Guardrails are not assumed active by default; they are explicitly verified by our local security check scripts.

## Active Local Controls in Repository
1. Secrets scanning (`scripts/security_check.py`) checking staged files, uncommitted files, and repository content for private keys, tokens, and keystores.
2. Supply-chain verification: manifest audits, pinned lockfiles, and permission reviews for Android/Flutter and Python.
3. Explicit permission requirements before commits, pushes, deployments, and dependency additions.
4. Execution ledger maintaining cryptographic verification and audit trails in `docs/STATUS.md`.
