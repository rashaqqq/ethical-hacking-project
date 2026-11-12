def normalize_alert(alert: dict) -> dict:
    return {
        "alert_id": alert.get("pluginId", ""),
        "name": alert.get("name", ""),
        "risk": alert.get("risk", ""),
        "confidence": alert.get("confidence", ""),
        "url": alert.get("url", ""),
        "method": alert.get("method", ""),
        "parameter": alert.get("param", ""),
        "description": alert.get("description", ""),
        "evidence": alert.get("evidence", ""),
        "solution": alert.get("solution", ""),
        "reference": alert.get("reference", ""),
        "cwe_id": alert.get("cweid", ""),
    }


def normalize_alerts(alerts: list[dict]) -> list[dict]:
    return [normalize_alert(alert) for alert in alerts]
