"""Offline publication checks; no cloud access or third-party packages needed."""
from pathlib import Path
import ast
import ipaddress
import json
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
errors = []
counts = {"json": 0, "python": 0, "xml": 0, "embedded_python": 0}
private_dirs = {".git", ".local", ".venv", "venv", "__pycache__", ".pytest_cache"}
safe_networks = [ipaddress.ip_network(n) for n in
                 ("10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                  "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

def check(condition, message):
    if not condition:
        errors.append(message)

for file in sorted(ROOT.rglob("*")):
    relative = file.relative_to(ROOT)
    if not file.is_file() or any(p in private_dirs for p in relative.parts):
        continue
    if file.name.endswith(".local.json") or file.suffix in {".pyc", ".png", ".jpg", ".mp4"}:
        continue
    try:
        text = file.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        errors.append(f"Unexpected binary file requires manual review: {relative}")
        continue
    try:
        if file.suffix == ".json":
            data = json.loads(text)
            counts["json"] += 1
            if relative.parts[0] == "infra":
                parameters = data.get("parameters", {})
                check(all(isinstance(v, dict) and "type" in v for v in parameters.values()), f"Invalid ARM parameter definition: {relative}")
                refs = set(re.findall(r"parameters\('([^']+)'\)", text))
                check(refs <= set(parameters), f"Undefined ARM parameters in {relative}: {refs - set(parameters)}")
                check(bool(data.get("resources")), f"Empty infrastructure template: {relative}")
                if "windowsAdminPassword" in parameters:
                    check(parameters["windowsAdminPassword"]["type"] == "secureString", "Windows admin password must be secureString")
        elif file.suffix == ".py":
            ast.parse(text, filename=str(relative))
            counts["python"] += 1
        elif file.suffix == ".xml":
            ET.fromstring(text)
            counts["xml"] += 1
        elif file.suffix == ".sh":
            for index, block in enumerate(re.findall(r"python3 - <<'PY'\n(.*?)\nPY", text, re.S)):
                ast.parse(block, filename=f"{relative}:embedded-{index}")
                counts["embedded_python"] += 1
    except (SyntaxError, ValueError, ET.ParseError, TypeError) as exc:
        errors.append(f"Invalid syntax in {relative}: {exc}")

    # Lightweight account-identifier checks. This is not a comprehensive scanner.
    check(not re.search(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|ENCRYPTED) PRIVATE KEY-----", text), f"Private key material: {relative}")
    check(not re.search(r"\beyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b", text), f"Possible JWT: {relative}")
    check(not re.search(r"C:[/\\]Users[/\\][^<\s]", text, re.I), f"Personal absolute Windows path: {relative}")
    check(not re.search(r"/subscriptions/[0-9a-f-]{36}", text, re.I), f"Azure subscription identifier: {relative}")
    for candidate in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        # Version strings are not endpoints. Azure platform virtual IP is public-looking.
        if candidate in {"168.63.129.16", "0.0.0.0"} or re.search(r'(?:contentVersion|version)["\s:]+["\']?' + re.escape(candidate), text):
            continue
        check(any(address in network for network in safe_networks), f"Non-documentation public IPv4 requires review: {relative}: {candidate}")
    if file.suffix == ".md":
        for target in re.findall(r"\]\(([^)]+)\)", text):
            if target.startswith(("https://", "http://", "mailto:", "#")):
                continue
            check((file.parent / target.split("#", 1)[0]).exists(), f"Broken local link: {relative} -> {target}")

# Prevent drift between published custom rule examples and installers.
for example, installer, marker in (
    ("application.xml", "install-siem.sh", "XML"),
    ("ips.xml", "install-ips-wazuh.sh", "EOF"),
    ("sudo-denial.xml", "purple-detection-fix.sh", "EOF"),
):
    src = (ROOT / "scripts/linux" / installer).read_text(encoding="utf-8")
    block = re.search(r"<<'" + marker + r"'\n(.*?)\n" + marker, src, re.S)
    expected = (ROOT / "detections/wazuh" / example).read_text(encoding="utf-8").strip()
    check(bool(block) and block.group(1).strip() == expected, f"Rule/installer mismatch: {example}")

data = json.loads((ROOT / "evidence/validation-summary.json").read_text(encoding="utf-8"))
check(data["detection_request"]["http_status"] == "404", "Recorded detection outcome mismatch")
check(data["prevention_request"]["curl_exit"] == 28, "Recorded prevention timeout missing")
check(data["normal_traffic_after_response"]["http_status"] == "200", "Recorded normal-traffic check missing")
check(any(e.get("action") == "blocked" and str(e.get("rule")) == "100110" for e in data["wazuh_events"]), "Matching Wazuh block evidence missing")

if errors:
    print("FAILED:")
    print("\n".join("- " + error for error in errors))
    sys.exit(1)
print("PASS:", ", ".join(f"{n} {label}" for label, n in counts.items()), "plus links, rule consistency and evidence checks")
print("Static publication checks only. Review secrets manually; no Azure resources were accessed.")
