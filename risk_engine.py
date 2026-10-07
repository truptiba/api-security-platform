def calculate_risk(findings):
    """
    Calculate overall API security risk score.

    Severity weights:
    HIGH   = 40
    MEDIUM = 20
    LOW    = 10
    """

    weights = {
        "HIGH": 40,
        "MEDIUM": 20,
        "LOW": 10
    }

    score = 0

    for finding in findings:
        severity = finding.get("severity", "").upper()
        score += weights.get(severity, 0)

    # Keep score within 0-100
    score = min(score, 100)

    return score


def get_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    else:
        return "SECURE"