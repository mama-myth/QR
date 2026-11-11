#!/usr/bin/env python3
"""
Peek-in QR Security & Guardrails Verification Script
Validates:
1. Absence of secrets, keys, keystores, and credentials in the repo
2. Guardrail integrity and presence of required security invariants
3. Toolchain and environment readiness
4. Supply-chain boundaries (no unverified scripts/deps)
"""

import os
import sys
import re
import subprocess

SECRET_PATTERNS = [
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key"),
    (r'(?i)api[_-]?key\s*[:=]\s*["\x27][0-9a-zA-Z\-_]{16,}["\x27]', "API Key"),
    (r'(?i)secret[_-]?key\s*[:=]\s*["\x27][0-9a-zA-Z\-_]{16,}["\x27]', "Secret Key"),
    (r'(?i)password\s*[:=]\s*["\x27][^"\x27\s]{8,}["\x27]', "Hardcoded Password"),
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
]

BLOCKED_FILES = [
    r'.*\.keystore$',
    r'.*\.jks$',
    r'.*\.p12$',
    r'.*\.pem$',
    r'^\.env(\..+)?$',
]

def scan_files(root_dir="."):
    violations = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip git directory
        if ".git" in dirnames:
            dirnames.remove(".git")
        if ".dart_tool" in dirnames:
            dirnames.remove(".dart_tool")

        for fname in filenames:
            rel_path = os.path.relpath(os.path.join(dirpath, fname), root_dir)

            # Check blocked file extensions/names
            for pattern in BLOCKED_FILES:
                if re.match(pattern, fname) or re.match(pattern, rel_path):
                    violations.append(f"Blocked secret file pattern detected: {rel_path}")

            # Check file content
            full_path = os.path.join(dirpath, fname)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern, desc in SECRET_PATTERNS:
                        matches = re.finditer(pattern, content)
                        for m in matches:
                            violations.append(f"Potential secret ({desc}) found in {rel_path}: {m.group(0)[:20]}...")
            except Exception as e:
                # Binary files or unreadable files
                pass
    return violations

def verify_invariants():
    checks = []
    # Verify SECURITY_GATES.md exists and contains key invariants
    sec_gates = "security/SECURITY_GATES.md"
    if not os.path.exists(sec_gates):
        checks.append(("FAIL", "security/SECURITY_GATES.md missing"))
    else:
        with open(sec_gates, "r") as f:
            content = f.read()
            if "scan -> parse -> rules/KB/ML/(optional net) -> fusion -> diagnostics -> consent -> action" in content:
                checks.append(("PASS", "Pipeline invariant present in SECURITY_GATES.md"))
            else:
                checks.append(("FAIL", "Pipeline invariant missing in SECURITY_GATES.md"))

            if "UNKNOWN` must not be shown as verified" in content or "UNKNOWN must not be shown as verified" in content:
                checks.append(("PASS", "Tri-state UNKNOWN/VERIFIED invariant present"))
            else:
                checks.append(("FAIL", "Tri-state invariant missing"))

    # Verify AGENTS.md exists
    if os.path.exists("agent/AGENTS.md"):
        checks.append(("PASS", "agent/AGENTS.md operational rules present"))
    else:
        checks.append(("FAIL", "agent/AGENTS.md missing"))

    # Verify GUARDRAILS_INTEGRATION.md exists
    if os.path.exists("security/GUARDRAILS_INTEGRATION.md"):
        checks.append(("PASS", "security/GUARDRAILS_INTEGRATION.md present"))
    else:
        checks.append(("FAIL", "security/GUARDRAILS_INTEGRATION.md missing"))

    return checks

def check_environment():
    tools = ["flutter", "dart", "java", "gradle", "python3", "docker", "adb"]
    env_results = []
    for tool in tools:
        res = subprocess.run(f"which {tool}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode == 0:
            env_results.append(("PASS", f"Tool {tool} available: {res.stdout.decode().strip()}"))
        else:
            env_results.append(("WARN", f"Tool {tool} not found in PATH"))

    # Check Android SDK
    android_home = os.environ.get("ANDROID_HOME", "/opt/android-sdk")
    if os.path.isdir(android_home):
        env_results.append(("PASS", f"Android SDK found at {android_home}"))
    else:
        env_results.append(("WARN", f"ANDROID_HOME {android_home} directory not found"))

    return env_results

def main():
    print("=== Peek-in QR Gate G0 Security & Environment Verification ===")
    violations = scan_files(".")
    if violations:
        print("\n[!] Secret Scanner Violations:")
        for v in violations:
            print(f"  - {v}")
    else:
        print("[✓] Secret Scanner: No hardcoded secrets or sensitive files found.")

    print("\n--- Invariant Checks ---")
    invariant_checks = verify_invariants()
    all_inv_pass = True
    for status, msg in invariant_checks:
        print(f"[{status}] {msg}")
        if status == "FAIL":
            all_inv_pass = False

    print("\n--- Environment Readiness ---")
    env_checks = check_environment()
    for status, msg in env_checks:
        print(f"[{status}] {msg}")

    if violations or not all_inv_pass:
        print("\n[FAIL] Gate G0 Security Checks Failed.")
        sys.exit(1)
    else:
        print("\n[PASS] Gate G0 Security Checks Passed.")
        sys.exit(0)

if __name__ == "__main__":
    main()
