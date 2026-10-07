import requests
import time


CANDIDATE_ENDPOINTS = [
    ("/users", "GET"),
    ("/products", "GET"),
    ("/admin", "GET"),

    # Controlled discovery candidates
    ("/debug", "GET"),
    ("/internal", "GET"),
    ("/metrics", "GET"),
    ("/health", "GET"),
    ("/swagger", "GET"),
    ("/v1/users", "GET"),
    ("/api/admin", "GET")
]


def get_documented_endpoints(base_url):
    url = base_url.rstrip("/") + "/openapi.json"

    response = requests.get(url, timeout=5)
    response.raise_for_status()

    data = response.json()

    documented = set()

    for path, methods in data.get("paths", {}).items():
        for method in methods:
            if method.upper() in {
                "GET", "POST", "PUT", "PATCH", "DELETE"
            }:
                documented.add((path, method.upper()))

    return documented


def discover_endpoints(base_url):
    discovered = []

    for path, method in CANDIDATE_ENDPOINTS:

        url = base_url.rstrip("/") + path

        try:
            response = requests.get(url, timeout=5)

            # 2xx, 3xx, and expected 4xx responses still prove
            # that the endpoint exists.
            if response.status_code != 404:

                authentication_required = path == "/admin"

                discovered.append({
                    "path": path,
                    "method": method,
                    "status": response.status_code,
                    "authentication_required": authentication_required
                })

        except requests.RequestException:
            pass

    return discovered
def run_authorization_check(base_url, endpoint):
    path = endpoint["path"]
    method = endpoint["method"]

    if path != "/admin":
        return {
            "path": path,
            "method": method,
            "test_type": "authorization",
            "rule_id": "AUTHZ-001",
            "status": "PASS",
            "severity": "LOW",
            "evidence": (
                f"{method} {path} is not classified as an admin endpoint."
            )
        }

    url = base_url.rstrip("/") + path

    try:
        response = requests.get(url, timeout=5)

        if response.status_code in [200, 201, 202, 204]:
            return {
                "path": path,
                "method": method,
                "test_type": "authorization",
                "rule_id": "AUTHZ-001",
                "status": "FAIL",
                "severity": "MEDIUM",
                "evidence": (
                    f"{method} {path} returned HTTP "
                    f"{response.status_code} without an authorization token."
                )
            }

        return {
            "path": path,
            "method": method,
            "test_type": "authorization",
            "rule_id": "AUTHZ-001",
            "status": "PASS",
            "severity": "LOW",
            "evidence": (
                f"{method} {path} returned HTTP "
                f"{response.status_code} when accessed without authorization."
            )
        }

    except requests.RequestException as e:
        return {
            "path": path,
            "method": method,
            "test_type": "authorization",
            "rule_id": "AUTHZ-001",
            "status": "ERROR",
            "severity": "LOW",
            "evidence": (
                f"Authorization test failed to execute: {str(e)}"
            )
        }


def run_rate_policy_check(base_url, endpoint):
    path = endpoint["path"]
    method = endpoint["method"]

    url = base_url.rstrip("/") + path

    request_count = 5
    rate_limited = False
    last_status = None

    try:
        start_time = time.time()

        for _ in range(request_count):
            response = requests.get(url, timeout=5)
            last_status = response.status_code

            if response.status_code == 429:
                rate_limited = True
                break

        elapsed = round(time.time() - start_time, 3)

        if rate_limited:
            return {
                "path": path,
                "method": method,
                "test_type": "rate_policy",
                "rule_id": "RATE-001",
                "status": "PASS",
                "severity": "LOW",
                "evidence": (
                    f"{method} {path} returned HTTP 429 after "
                    f"controlled requests. Rate limiting is active."
                )
            }

        return {
            "path": path,
            "method": method,
            "test_type": "rate_policy",
            "rule_id": "RATE-001",
            "status": "FAIL",
            "severity": "MEDIUM",
            "evidence": (
                f"{request_count} controlled requests to {method} {path} "
                f"completed without HTTP 429. "
                f"Elapsed time: {elapsed}s. Last status: {last_status}."
            )
        }

    except requests.RequestException as e:
        return {
            "path": path,
            "method": method,
            "test_type": "rate_policy",
            "rule_id": "RATE-001",
            "status": "ERROR",
            "severity": "LOW",
            "evidence": (
                f"Rate-policy test failed to execute: {str(e)}"
            )
        }


def run_safe_fuzz_test(base_url, endpoint):
    path = endpoint["path"]
    method = endpoint["method"]

    url = base_url.rstrip("/") + path

    try:
        response = requests.get(
            url,
            params={"security_test_invalid": "unexpected-value"},
            timeout=5
        )

        if response.status_code >= 500:
            return {
                "path": path,
                "method": method,
                "test_type": "safe_fuzz",
                "rule_id": "FUZZ-001",
                "status": "FAIL",
                "severity": "MEDIUM",
                "evidence": (
                    f"{method} {path} returned HTTP "
                    f"{response.status_code} when given a harmless "
                    f"unexpected parameter."
                )
            }

        return {
            "path": path,
            "method": method,
            "test_type": "safe_fuzz",
            "rule_id": "FUZZ-001",
            "status": "PASS",
            "severity": "LOW",
            "evidence": (
                f"{method} {path} handled a harmless unexpected "
                f"parameter with HTTP {response.status_code}."
            )
        }

    except requests.RequestException as e:
        return {
            "path": path,
            "method": method,
            "test_type": "safe_fuzz",
            "rule_id": "FUZZ-001",
            "status": "ERROR",
            "severity": "LOW",
            "evidence": (
                f"Safe fuzz test failed to execute: {str(e)}"
            )
        }


def run_security_tests(base_url, discovered):
    results = []

    for endpoint in discovered:

        authorization_result = run_authorization_check(
            base_url,
            endpoint
        )

        rate_result = run_rate_policy_check(
            base_url,
            endpoint
        )

        fuzz_result = run_safe_fuzz_test(
            base_url,
            endpoint
        )

        results.append(authorization_result)
        results.append(rate_result)
        results.append(fuzz_result)

    return results