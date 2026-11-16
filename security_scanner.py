
import requests
import argparse
import json
import re
from urllib.parse import urlparse
from http.cookies import SimpleCookie

TIMEOUT = 15

SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "Enforces HTTPS connections.",
    "Content-Security-Policy":
        "Helps prevent cross-site scripting (XSS).",
    "X-Content-Type-Options":
        "Prevents MIME-type sniffing.",
    "X-Frame-Options":
        "Helps prevent clickjacking.",
    "Referrer-Policy":
        "Controls referrer information.",
    "Permissions-Policy":
        "Restricts browser features and APIs."
}

LEAKAGE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via"
]

SUSPICIOUS_ERRORS = [
    "traceback (most recent call last)",
    "stack trace",
    "sql syntax",
    "uncaught exception",
    "fatal error:",
    "debug mode"
]


def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid HTTP or HTTPS URL.")

    return url


def get_cookies(response):
    try:
        return response.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        value = response.headers.get("Set-Cookie")
        return [value] if value else []


def scan_security_headers(response):
    print("\n[1] SECURITY HEADERS")

    findings = []

    for header, description in SECURITY_HEADERS.items():
        value = response.headers.get(header)

        # HSTS is relevant to HTTPS sites.
        if header == "Strict-Transport-Security":
            if response.url.startswith("http://"):
                print("[INFO] HSTS check skipped: final URL is HTTP.")
                continue

        if value:
            print(f"[PASS] {header}: {value}")
        else:
            print(f"[WARNING] Missing {header}")
            findings.append({
                "severity": "Medium",
                "issue": f"Missing {header}",
                "recommendation": description
            })

    return findings


def scan_information_leakage(response):
    print("\n[2] INFORMATION LEAKAGE")

    findings = []

    for header in LEAKAGE_HEADERS:
        value = response.headers.get(header)

        if value:
            print(f"[WARNING] {header}: {value}")

            findings.append({
                "severity": "Low",
                "issue": f"Technology disclosure through {header}",
                "evidence": value,
                "recommendation":
                    "Consider reducing unnecessary technology and version disclosure."
            })

    body = response.text[:500000].lower()

    for error in SUSPICIOUS_ERRORS:
        if error in body:
            print(f"[WARNING] Possible exposed error information: {error}")

            findings.append({
                "severity": "High",
                "issue": "Possible debug or error information exposure",
                "evidence": error,
                "recommendation":
                    "Disable public debug output and use generic error pages."
            })

    if not findings:
        print("[PASS] No obvious information leakage detected.")

    return findings


def scan_cookies(response):
    print("\n[3] COOKIE SECURITY")

    findings = []
    cookies = get_cookies(response)

    if not cookies:
        print("[INFO] No Set-Cookie headers detected.")
        return findings

    for cookie_string in cookies:
        parsed = SimpleCookie()

        try:
            parsed.load(cookie_string)
        except Exception:
            continue

        for name, cookie in parsed.items():
            print(f"\nCookie: {name}")

            if cookie["secure"]:
                print("[PASS] Secure")
            else:
                print("[WARNING] Missing Secure flag")
                findings.append({
                    "severity": "Medium",
                    "issue": f"Cookie {name} missing Secure flag",
                    "recommendation":
                        "Set Secure on cookies transmitted over HTTPS."
                })

            if cookie["httponly"]:
                print("[PASS] HttpOnly")
            else:
                print("[WARNING] Missing HttpOnly flag")
                findings.append({
                    "severity": "Medium",
                    "issue": f"Cookie {name} missing HttpOnly flag",
                    "recommendation":
                        "Set HttpOnly on cookies that do not need JavaScript access."
                })

            same_site = cookie["samesite"]

            if same_site:
                print(f"[PASS] SameSite={same_site}")
            else:
                print("[WARNING] Missing SameSite")
                findings.append({
                    "severity": "Low",
                    "issue": f"Cookie {name} missing SameSite",
                    "recommendation":
                        "Configure an appropriate SameSite policy."
                })

    return findings


def scan_cors(url, response):
    print("\n[4] CORS CONFIGURATION")

    findings = []

    test_origin = "https://scanner-test.invalid"

    allow_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    allow_credentials = response.headers.get(
        "Access-Control-Allow-Credentials", ""
    ).lower()

    if allow_origin:
        print(f"Access-Control-Allow-Origin: {allow_origin}")
        print(f"Access-Control-Allow-Credentials: {allow_credentials}")

        if allow_origin == "*":
            print("[WARNING] Wildcard CORS origin detected.")

            findings.append({
                "severity": "Medium",
                "issue": "Wildcard CORS policy",
                "recommendation":
                    "Restrict allowed origins to trusted domains."
            })

        if allow_origin == "*" and allow_credentials == "true":
            print("[WARNING] Wildcard and credentials combination detected.")

        if allow_origin == test_origin:
            print("[WARNING] Untrusted origin appears to be reflected.")

            findings.append({
                "severity": "High",
                "issue": "Untrusted origin reflected in CORS response",
                "recommendation":
                    "Use an explicit allowlist of trusted origins."
            })
    else:
        print("[INFO] No CORS allow-origin header on normal response.")

    # Send a separate request using an untrusted test origin.
    try:
        cors_response = requests.get(
            url,
            headers={"Origin": test_origin},
            timeout=TIMEOUT,
            allow_redirects=True
        )

        reflected_origin = cors_response.headers.get(
            "Access-Control-Allow-Origin"
        )

        credentials = cors_response.headers.get(
            "Access-Control-Allow-Credentials", ""
        ).lower()

        if reflected_origin == test_origin:
            print("[WARNING] Server reflects an untrusted Origin.")

            if not any(
                item["issue"] == "Untrusted origin reflected in CORS response"
                for item in findings
            ):
                findings.append({
                    "severity": "High",
                    "issue": "Untrusted origin reflected in CORS response",
                    "recommendation":
                        "Validate Origin against a trusted allowlist."
                })

            if credentials == "true":
                print("[WARNING] CORS allows credentials for reflected origin.")

                findings.append({
                    "severity": "High",
                    "issue": "Credentials allowed for reflected origin",
                    "recommendation":
                        "Never trust arbitrary origins when allowing credentials."
                })

        elif reflected_origin == "*":
            print("[WARNING] Wildcard CORS policy confirmed.")

        else:
            print("[PASS] No reflection of the test origin detected.")

    except requests.RequestException as error:
        print(f"[ERROR] CORS test failed: {error}")

    return findings


def run_scan(url):
    findings = []

    print("=" * 60)
    print("       PYTHON WEB SECURITY HEADERS SCANNER")
    print("=" * 60)
    print(f"Target: {url}")

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            headers={
                "User-Agent": "AuthorizedSecurityScanner/1.0"
            }
        )

        print(f"Status Code: {response.status_code}")
        print(f"Final URL: {response.url}")

        findings += scan_security_headers(response)
        findings += scan_information_leakage(response)
        findings += scan_cookies(response)
        findings += scan_cors(url, response)

    except requests.RequestException as error:
        print(f"\n[ERROR] Unable to scan target: {error}")
        return

    print("\n" + "=" * 60)
    print("                 SCAN SUMMARY")
    print("=" * 60)

    print(f"Total findings: {len(findings)}")

    for severity in ["High", "Medium", "Low"]:
        count = sum(
            1 for item in findings
            if item["severity"] == severity
        )
        print(f"{severity}: {count}")

    report = {
        "target": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "total_findings": len(findings),
        "findings": findings
    }

    with open("security_report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\n[+] Report saved to security_report.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Python Web Security Headers Scanner"
    )

    parser.add_argument(
        "url",
        help="Target website URL"
    )

    args = parser.parse_args()

    try:
        target = validate_url(args.url)
        run_scan(target)
    except ValueError as error:
        print(f"[ERROR] {error}")
