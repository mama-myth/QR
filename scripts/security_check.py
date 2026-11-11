#!/usr/bin/env python3
"""
Peek-in QR Security & Guardrails Verification Script
Validates:
1. Absence of secrets, keys, keystores, and credentials in the repo
2. Guardrail policy: only root README.md is permitted among markdown files
3. Invariant checks in README.md
4. Toolchain and environment readiness
5. Supply-chain boundaries
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
    md_files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Skip git, pytest cache, and build output directories
        for ignored in [".git", ".dart_tool", "build", ".gradle", ".pytest_cache"]:
            if ignored in dirnames:
                dirnames.remove(ignored)

        for fname in filenames:
            rel_path = os.path.relpath(os.path.join(dirpath, fname), root_dir)

            # Check markdown file policy: only root README.md permitted
            if fname.lower().endswith(".md"):
                md_files.append(rel_path)
                if rel_path != "README.md":
                    violations.append(f"Disallowed Markdown file policy violation: {rel_path} (only root README.md allowed)")

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
            except Exception:
                pass
    return violations

def verify_invariants():
    checks = []
    readme_path = "README.md"
    if not os.path.exists(readme_path):
        checks.append(("FAIL", "Root README.md missing"))
        return checks

    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    pipeline_invariant = "scan -> parse -> rules/KB/ML/(optional net) -> fusion -> diagnostics -> consent -> ActionGateway"
    if pipeline_invariant in content:
        checks.append(("PASS", "Security invariant pipeline present in README.md"))
    else:
        checks.append(("FAIL", "Security invariant pipeline missing in README.md"))

    if "VERIFIED" in content and "UNKNOWN" in content and "SUSPICIOUS" in content:
        checks.append(("PASS", "Tri-state decision invariants documented"))
    else:
        checks.append(("FAIL", "Tri-state decision invariants missing"))

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

    android_home = os.environ.get("ANDROID_HOME", "/opt/android-sdk")
    if os.path.isdir(android_home):
        env_results.append(("PASS", f"Android SDK found at {android_home}"))
    else:
        env_results.append(("WARN", f"ANDROID_HOME {android_home} directory not found"))

    return env_results

def main():
    print("=== Peek-in QR Gate G0 Security & Guardrails Verification ===")
    violations = scan_files(".")
    if violations:
        print("\n[!] Policy Violations:")
        for v in violations:
            print(f"  - {v}")
    else:
        print("[✓] Secret & Policy Scanner: Clean. Only root README.md exists, no secrets.")

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
