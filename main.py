from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import connection

from scanner import (
    get_documented_endpoints,
    discover_endpoints,
    run_security_tests
)

from risk_engine import calculate_risk, get_risk_level


app = FastAPI(title="API Security Posture Platform")


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------
# Models
# ---------------------------------------------------------

class Target(BaseModel):
    name: str
    base_url: str
    openapi_url: str | None = None
class FindingUpdate(BaseModel):
    owner: str | None = None
    status: str | None = None
    due_date: str | None = None


class ExceptionRequest(BaseModel):
    requested_by: str
    reason: str


class ExceptionDecision(BaseModel):
    status: str


# ---------------------------------------------------------
# Basic routes
# ---------------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "API Security Platform is running"
    }


@app.get("/health")
def health():

    try:
        cursor = connection.cursor()

        cursor.execute("SELECT 1")

        cursor.close()

        return {
            "status": "healthy",
            "database": "connected"
        }

    except Exception as e:

        return {
            "status": "error",
            "database": str(e)
        }


# ---------------------------------------------------------
# Add target
# ---------------------------------------------------------

@app.post("/api/targets")
def add_target(target: Target):

    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO targets
        (name, base_url, openapi_url)
        VALUES (%s, %s, %s)
        RETURNING id;
        """,
        (
            target.name,
            target.base_url,
            target.openapi_url
        )
    )

    target_id = cursor.fetchone()[0]

    connection.commit()
    cursor.close()

    return {
        "message": "Target added successfully",
        "target_id": target_id
    }


# ---------------------------------------------------------
# Start security scan
# ---------------------------------------------------------

@app.post("/api/scans")
def start_scan(target_id: int):

    cursor = connection.cursor()

    # Get target
    cursor.execute(
        """
        SELECT base_url
        FROM targets
        WHERE id = %s;
        """,
        (target_id,)
    )

    target = cursor.fetchone()

    if not target:

        cursor.close()

        return {
            "error": "Target not found"
        }

    base_url = target[0]

    # -----------------------------------------------------
    # Discover documented and runtime endpoints
    # -----------------------------------------------------

    documented = get_documented_endpoints(base_url)

    discovered = discover_endpoints(base_url)

    # -----------------------------------------------------
    # Create scan
    # -----------------------------------------------------

    cursor.execute(
        """
        INSERT INTO scans
        (target_id, status, started_at)
        VALUES (%s, %s, CURRENT_TIMESTAMP)
        RETURNING id;
        """,
        (
            target_id,
            "running"
        )
    )

    scan_id = cursor.fetchone()[0]

    shadow_count = 0

    # Used for final risk calculation
    findings = []

    # -----------------------------------------------------
    # Endpoint inventory + existing security checks
    # -----------------------------------------------------

    for endpoint in discovered:

        path = endpoint["path"]
        method = endpoint["method"]
        status = endpoint["status"]

        authentication_required = endpoint[
            "authentication_required"
        ]

        is_documented = (
            path,
            method
        ) in documented

        # ---------------------------------------------
        # Store endpoint
        # ---------------------------------------------

        cursor.execute(
            """
            INSERT INTO endpoints
            (
                scan_id,
                path,
                method,
                documented,
                discovered,
                auth_required,
                source
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (
                scan_id,
                path,
                method,
                is_documented,
                True,
                authentication_required,
                "scanner"
            )
        )

        endpoint_id = cursor.fetchone()[0]

        # ---------------------------------------------
        # Shadow endpoint check
        # ---------------------------------------------

        if not is_documented:

            shadow_count += 1

            finding = {
                "severity": "HIGH"
            }

            findings.append(finding)

            cursor.execute(
                """
                INSERT INTO findings
                (
                    scan_id,
                    endpoint_id,
                    rule_id,
                    severity,
                    title,
                    description,
                    evidence,
                    remediation,
                    owner,
                    status
                )
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    scan_id,
                    endpoint_id,
                    "SHADOW-001",
                    "HIGH",
                    "Potential Shadow Endpoint",
                    "A live endpoint was discovered but is not present in the OpenAPI documentation.",
                    f"{method} {path} returned HTTP {status}.",
                    "Review the endpoint and either document it or remove it if it is no longer required.",
                    "Security Team",
                    "OPEN"
                )
            )

        # ---------------------------------------------
        # Authentication check
        # ---------------------------------------------

        if path == "/admin" and not authentication_required:

            finding = {
                "severity": "HIGH"
            }

            findings.append(finding)

            cursor.execute(
                """
                INSERT INTO findings
                (
                    scan_id,
                    endpoint_id,
                    rule_id,
                    severity,
                    title,
                    description,
                    evidence,
                    remediation,
                    owner,
                    status
                )
                VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    scan_id,
                    endpoint_id,
                    "AUTH-001",
                    "HIGH",
                    "Missing Authentication",
                    "The endpoint can be accessed without authentication.",
                    f"{method} {path} was accessible without authentication.",
                    "Protect the endpoint with appropriate authentication and authorization controls.",
                    "Security Team",
                    "OPEN"
                )
            )

    # -----------------------------------------------------
       # -----------------------------------------------------
    # NEW SECURITY TESTS
    # -----------------------------------------------------

    security_results = run_security_tests(
        base_url,
        discovered
    )

    for result in security_results:

        test_type = result["test_type"]
        rule_id = result["rule_id"]
        test_status = result["status"]
        severity = result["severity"]
        evidence = result["evidence"]

        # Find the correct endpoint using path + method
        test_path = result["path"]
        test_method = result["method"]

        cursor.execute(
            """
            SELECT id
            FROM endpoints
            WHERE scan_id = %s
            AND path = %s
            AND method = %s
            LIMIT 1;
            """,
            (
                scan_id,
                test_path,
                test_method
            )
        )

        endpoint_row = cursor.fetchone()

        if endpoint_row:
            endpoint_id = endpoint_row[0]
        else:
            endpoint_id = None

        # Store every security test
        if endpoint_id is not None:
            cursor.execute(
                """
                INSERT INTO security_tests
                (
                    scan_id,
                    endpoint_id,
                    test_type,
                    rule_id,
                    status,
                    severity,
                    evidence
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    scan_id,
                    endpoint_id,
                    test_type,
                    rule_id,
                    test_status,
                    severity,
                    evidence
                )
            )

        # Only failed security tests become findings
        if test_status == "FAIL":

            findings.append({
                "severity": severity
            })

            title_map = {
                "AUTHZ-001": "Authorization Check Failed",
                "RATE-001": "Missing Rate Limiting",
                "FUZZ-001": "Unsafe Input Handling"
            }

            description_map = {
                "AUTHZ-001": "The endpoint was accessible without the expected authorization control.",
                "RATE-001": "The endpoint did not return HTTP 429 during the controlled rate-policy test.",
                "FUZZ-001": "The endpoint returned a server error when given a harmless unexpected parameter."
            }

            remediation_map = {
                "AUTHZ-001": "Apply appropriate authorization controls to the endpoint.",
                "RATE-001": "Configure rate limiting for the endpoint.",
                "FUZZ-001": "Validate and safely handle unexpected input."
            }

            cursor.execute(
                """
                INSERT INTO findings
                (
                    scan_id,
                    endpoint_id,
                    rule_id,
                    severity,
                    title,
                    description,
                    evidence,
                    remediation,
                    owner,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """,
                (
                    scan_id,
                    endpoint_id,
                    rule_id,
                    severity,
                    title_map.get(rule_id, "Security Test Failed"),
                    description_map.get(
                        rule_id,
                        "A security test failed."
                    ),
                    evidence,
                    remediation_map.get(
                        rule_id,
                        "Review and remediate the identified security issue."
                    ),
                    "Security Team",
                    "OPEN"
                )
            )
    # -----------------------------------------------------
    # Calculate risk
    # -----------------------------------------------------

    risk_score = calculate_risk(findings)

    risk_level = get_risk_level(
        risk_score
    )

    # -----------------------------------------------------
    # Complete scan
    # -----------------------------------------------------

    cursor.execute(
        """
        UPDATE scans
        SET
            status = %s,
            finished_at = CURRENT_TIMESTAMP,
            total_endpoints = %s,
            shadow_count = %s,
            risk_score = %s
        WHERE id = %s;
        """,
        (
            "completed",
            len(discovered),
            shadow_count,
            risk_score,
            scan_id
        )
    )

    connection.commit()

    cursor.close()

    return {
        "message": "Scan completed successfully",
        "scan_id": scan_id,
        "total_endpoints": len(discovered),
        "shadow_endpoints": shadow_count,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "security_tests": len(security_results)
    }


# ---------------------------------------------------------
# Get scan
# ---------------------------------------------------------

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: int):

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target_id,
            status,
            started_at,
            finished_at,
            total_endpoints,
            shadow_count,
            risk_score
        FROM scans
        WHERE id = %s;
        """,
        (scan_id,)
    )

    scan = cursor.fetchone()

    cursor.close()

    if not scan:

        return {
            "error": "Scan not found"
        }

    risk_score = float(
        scan[7]
    )

    return {
        "scan_id": scan[0],
        "target_id": scan[1],
        "status": scan[2],
        "started_at": scan[3],
        "finished_at": scan[4],
        "total_endpoints": scan[5],
        "shadow_endpoints": scan[6],
        "risk_score": risk_score,
        "risk_level": get_risk_level(risk_score)
    }


# ---------------------------------------------------------
# Endpoint inventory
# ---------------------------------------------------------

@app.get("/api/scans/{scan_id}/endpoints")
def get_endpoints(scan_id: int):

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            path,
            method,
            documented,
            discovered,
            auth_required,
            source
        FROM endpoints
        WHERE scan_id = %s
        ORDER BY id;
        """,
        (scan_id,)
    )

    rows = cursor.fetchall()

    cursor.close()

    endpoints = []

    for row in rows:

        endpoints.append({
            "endpoint_id": row[0],
            "path": row[1],
            "method": row[2],
            "documented": row[3],
            "discovered": row[4],
            "auth_required": row[5],
            "source": row[6]
        })

    return {
        "scan_id": scan_id,
        "total": len(endpoints),
        "endpoints": endpoints
    }


# ---------------------------------------------------------
# Findings
# ---------------------------------------------------------

@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: int):

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            endpoint_id,
            rule_id,
            severity,
            title,
            description,
            evidence,
            remediation,
            owner,
            status,
            due_date,
            closed_at
        FROM findings
        WHERE scan_id = %s
        ORDER BY id;
        """,
        (scan_id,)
    )

    rows = cursor.fetchall()

    cursor.close()

    findings = []

    for row in rows:

        findings.append({
            "finding_id": row[0],
            "endpoint_id": row[1],
            "rule_id": row[2],
            "severity": row[3],
            "title": row[4],
            "description": row[5],
            "evidence": row[6],
            "remediation": row[7],
            "owner": row[8],
            "status": row[9],
            "due_date": row[10],
            "closed_at": row[11]
        })

    return {
        "scan_id": scan_id,
        "total": len(findings),
        "findings": findings
    }


# ---------------------------------------------------------
# Security tests
# ---------------------------------------------------------

@app.get("/api/scans/{scan_id}/security-tests")
def get_security_tests(scan_id: int):

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            endpoint_id,
            test_type,
            rule_id,
            status,
            severity,
            evidence,
            created_at
        FROM security_tests
        WHERE scan_id = %s
        ORDER BY id;
        """,
        (scan_id,)
    )

    rows = cursor.fetchall()

    cursor.close()

    tests = []

    for row in rows:

        tests.append({
            "test_id": row[0],
            "endpoint_id": row[1],
            "test_type": row[2],
            "rule_id": row[3],
            "status": row[4],
            "severity": row[5],
            "evidence": row[6],
            "created_at": row[7]
        })

    return {
        "scan_id": scan_id,
        "total": len(tests),
        "tests": tests
    }


# ---------------------------------------------------------
# Scan history
# ---------------------------------------------------------

@app.get("/api/scans")
def get_scan_history():

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            target_id,
            status,
            started_at,
            finished_at,
            total_endpoints,
            shadow_count,
            risk_score
        FROM scans
        ORDER BY id DESC;
        """
    )

    rows = cursor.fetchall()

    cursor.close()

    scans = []

    for row in rows:

        risk_score = (
            float(row[7])
            if row[7] is not None
            else 0
        )

        scans.append({
            "scan_id": row[0],
            "target_id": row[1],
            "status": row[2],
            "started_at": row[3],
            "finished_at": row[4],
            "total_endpoints": row[5],
            "shadow_endpoints": row[6],
            "risk_score": risk_score,
            "risk_level": get_risk_level(risk_score)
        })

    return {
        "total": len(scans),
        "scans": scans
    }




    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            total_endpoints,
            shadow_count,
            risk_score,
            started_at
        FROM scans
        WHERE status = 'completed'
        ORDER BY id DESC
        LIMIT 2;
        """
    )

    rows = cursor.fetchall()

    cursor.close()

    if len(rows) < 2:

        return {
            "message":
                "At least two completed scans are required for comparison."
        }

    latest = rows[0]
    previous = rows[1]

    latest_score = float(latest[3])
    previous_score = float(previous[3])

    return {
        "latest_scan": {
            "scan_id": latest[0],
            "total_endpoints": latest[1],
            "shadow_endpoints": latest[2],
            "risk_score": latest_score,
            "risk_level": get_risk_level(latest_score)
        },

        "previous_scan": {
            "scan_id": previous[0],
            "total_endpoints": previous[1],
            "shadow_endpoints": previous[2],
            "risk_score": previous_score,
            "risk_level": get_risk_level(previous_score)
        },

        "risk_score_change":
            latest_score - previous_score,

        "shadow_endpoint_change":
            latest[2] - previous[2]
    }

@app.put("/api/findings/{finding_id}")
def update_finding(
    finding_id: int,
    update: FindingUpdate
):


    cursor = connection.cursor()

    # Check that finding exists
    cursor.execute(
        """
        SELECT id
        FROM findings
        WHERE id = %s;
        """,
        (finding_id,)
    )

    finding = cursor.fetchone()

    if not finding:
        cursor.close()

        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    # Update finding
    cursor.execute(
        """
        UPDATE findings
        SET
            owner = COALESCE(%s, owner),
            status = COALESCE(%s, status),
            due_date = %s,
            closed_at =
                CASE
                    WHEN %s = 'CLOSED'
                    THEN CURRENT_TIMESTAMP
                    ELSE closed_at
                END
        WHERE id = %s;
        """,
        (
            update.owner,
            update.status,
            update.due_date,
            update.status,
            finding_id
        )
    )

    connection.commit()
    cursor.close()

    return {
        "message": "Finding updated successfully",
        "finding_id": finding_id
    }


# ---------------------------------------------------------
# Create exception request
# ---------------------------------------------------------

@app.post("/api/findings/{finding_id}/exceptions")
def create_exception(
    finding_id: int,
    exception_request: ExceptionRequest
):

    cursor = connection.cursor()

    # Check finding
    cursor.execute(
        """
        SELECT id
        FROM findings
        WHERE id = %s;
        """,
        (finding_id,)
    )

    finding = cursor.fetchone()

    if not finding:
        cursor.close()

        raise HTTPException(
            status_code=404,
            detail="Finding not found"
        )

    # Create exception
    cursor.execute(
        """
        INSERT INTO exceptions
        (
            finding_id,
            requested_by,
            reason,
            status
        )
        VALUES
        (%s, %s, %s, %s)
        RETURNING id;
        """,
        (
            finding_id,
            exception_request.requested_by,
            exception_request.reason,
            "PENDING"
        )
    )

    exception_id = cursor.fetchone()[0]

    connection.commit()
    cursor.close()

    return {
        "message": "Exception request submitted",
        "exception_id": exception_id,
        "status": "PENDING"
    }


# ---------------------------------------------------------
# Get exceptions for a finding
# ---------------------------------------------------------

@app.get("/api/findings/{finding_id}/exceptions")
def get_exceptions(finding_id: int):

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            requested_by,
            reason,
            status,
            created_at,
            approved_at
        FROM exceptions
        WHERE finding_id = %s
        ORDER BY id DESC;
        """,
        (finding_id,)
    )

    rows = cursor.fetchall()

    cursor.close()

    exceptions = []

    for row in rows:

        exceptions.append({
            "exception_id": row[0],
            "requested_by": row[1],
            "reason": row[2],
            "status": row[3],
            "created_at": row[4],
            "approved_at": row[5]
        })

    return {
        "finding_id": finding_id,
        "total": len(exceptions),
        "exceptions": exceptions
    }


# ---------------------------------------------------------
# Approve / reject exception
# ---------------------------------------------------------

@app.put("/api/exceptions/{exception_id}")
def decide_exception(
    exception_id: int,
    decision: ExceptionDecision
):

    allowed_statuses = {
        "APPROVED",
        "REJECTED"
    }

    if decision.status not in allowed_statuses:

        raise HTTPException(
            status_code=400,
            detail="Status must be APPROVED or REJECTED"
        )

    cursor = connection.cursor()

    # Check exception
    cursor.execute(
        """
        SELECT id
        FROM exceptions
        WHERE id = %s;
        """,
        (exception_id,)
    )

    exception = cursor.fetchone()

    if not exception:

        cursor.close()

        raise HTTPException(
            status_code=404,
            detail="Exception not found"
        )

    cursor.execute(
        """
        UPDATE exceptions
        SET
            status = %s,
            approved_at = CURRENT_TIMESTAMP
        WHERE id = %s;
        """,
        (
            decision.status,
            exception_id
        )
    )

    connection.commit()
    cursor.close()

    return {
        "message": "Exception decision updated",
        "exception_id": exception_id,
        "status": decision.status
    }
