"""Перевірка відповіді NVD та аналіз за варіантом №5."""

import math
from copy import deepcopy

RULE = {
    "threshold": 7.0,
    "field": "confidentialityImpact",
    "expected": "HIGH",
}

ALLOWED_IMPACTS = ("NONE", "LOW", "HIGH")


def require(condition: bool, message: str) -> None:
    """Перевірка відповідності даних контракту."""
    if not condition:
        raise ValueError(message)


def optional_string(data: dict, field: str) -> str | None:
    """Перевірка необов'язкового рядкового поля."""
    if field not in data:
        return None

    value = data[field]

    require(
        isinstance(value, str) and bool(value.strip()),
        f"Некоректне поле {field}.",
    )

    return value


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Повертає словник зі статусом, описом і вибраною оцінкою CVSS."""

    require(
        isinstance(payload, dict),
        "Відповідь NVD має бути словником.",
    )

    vulnerabilities = payload.get("vulnerabilities")

    require(
        isinstance(vulnerabilities, list),
        "vulnerabilities має бути списком.",
    )

    if not vulnerabilities:
        return None

    require(
        len(vulnerabilities) == 1,
        "Очікується не більше одного запису CVE.",
    )

    item = vulnerabilities[0]

    require(
        isinstance(item, dict),
        "Некоректний запис vulnerability.",
    )

    cve = item.get("cve")

    require(
        isinstance(cve, dict),
        "Некоректна структура cve.",
    )

    require(
        cve.get("id") == cve_id,
        "Ідентифікатор CVE не збігається.",
    )

    status = optional_string(cve, "vulnStatus")
    descriptions = cve.get("descriptions", [])

    require(
        isinstance(descriptions, list),
        "descriptions має бути списком.",
    )

    description = None

    for entry in descriptions:
        require(
            isinstance(entry, dict),
            "Некоректний об'єкт опису.",
        )

        lang = entry.get("lang")
        value = entry.get("value")

        require(
            isinstance(lang, str) and isinstance(value, str),
            "Некоректні поля опису.",
        )

        if lang == "en" and value.strip() and description is None:
            description = value

    record = {
        "description": description,
        "vuln_status": status,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "cvss_data": {},
    }

    if status is None or status == "Rejected":
        return record

    metrics = cve.get("metrics", {})

    require(
        isinstance(metrics, dict),
        "metrics має бути словником.",
    )

    scores = metrics.get("cvssMetricV31", [])

    require(
        isinstance(scores, list),
        "cvssMetricV31 має бути списком.",
    )

    if not scores:
        return record

    require(
        all(isinstance(entry, dict) for entry in scores),
        "Некоректний елемент списку CVSS.",
    )

    selected = next(
        (entry for entry in scores if entry.get("type") == "Primary"),
        scores[0],
    )

    cvss_data = selected.get("cvssData")

    require(
        isinstance(cvss_data, dict),
        "cvssData має бути словником.",
    )

    score = cvss_data.get("baseScore")

    require(
        isinstance(score, (int, float))
        and not isinstance(score, bool)
        and 0 <= score <= 10
        and math.isfinite(score),
        "Некоректне значення baseScore.",
    )

    version = optional_string(cvss_data, "version")

    require(
        version is None or version == "3.1",
        "Очікується CVSS версії 3.1.",
    )

    record.update(
        {
            "cvss_version": version,
            "score": score,
            "score_source": optional_string(selected, "source"),
            "vector": optional_string(cvss_data, "vectorString"),
            "cvss_data": deepcopy(cvss_data),
        }
    )

    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Формує JSON-звіт відповідно до правила варіанта №5."""

    require(
        type(variant) is int and variant == 5,
        "Ця реалізація призначена для варіанта №5.",
    )

    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE.copy(),
        "observed": None,
        "decision": "not_found",
    }

    if record is None:
        return report

    for field in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
    ):
        report[field] = record[field]

    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report

    if record["vuln_status"] is None or record["score"] is None:
        report["decision"] = "insufficient_data"
        return report

    cvss_data = record["cvss_data"]
    field = RULE["field"]

    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report

    observed = cvss_data[field]

    require(
        observed in ALLOWED_IMPACTS,
        f"Некоректне значення {field}.",
    )

    report["observed"] = observed

    if record["score"] >= RULE["threshold"] and observed == RULE["expected"]:
        report["decision"] = "review"
    else:
        report["decision"] = "other"

    return report
