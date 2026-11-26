"""Тести аналізу вразливостей за варіантом №5."""

from copy import deepcopy

import pytest

from labs.lab04.analysis import build_report, extract_record

CVE_ID = "CVE-2099-10001"
VARIANT = 5


def get_cve(payload):
    return payload["vulnerabilities"][0]["cve"]


def get_cvss(payload):
    return get_cve(payload)["metrics"]["cvssMetricV31"][0]["cvssData"]


def make_report(payload):
    record = extract_record(payload, CVE_ID)
    return build_report(record, CVE_ID, VARIANT)


@pytest.mark.parametrize(
    "score, impact, expected",
    [
        (6.9, "HIGH", "other"),
        (7.0, "HIGH", "review"),
        (7.1, "HIGH", "review"),
        (9.8, "HIGH", "review"),
        (9.8, "LOW", "other"),
        (9.8, "NONE", "other"),
        (0, "HIGH", "other"),
        (10, "HIGH", "review"),
    ],
)
def test_variant_rule(sample_payload, score, impact, expected):
    cvss = get_cvss(sample_payload)
    cvss["baseScore"] = score
    cvss["confidentialityImpact"] = impact

    assert make_report(sample_payload)["decision"] == expected


def test_not_found():
    report = make_report({"vulnerabilities": []})

    assert report["decision"] == "not_found"
    assert report["score"] is None
    assert report["observed"] is None


def test_rejected(sample_payload):
    get_cve(sample_payload)["vulnStatus"] = "Rejected"

    report = make_report(sample_payload)

    assert report["decision"] == "rejected"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_status(sample_payload):
    del get_cve(sample_payload)["vulnStatus"]

    report = make_report(sample_payload)

    assert report["decision"] == "insufficient_data"
    assert report["score"] is None


def test_missing_metrics(sample_payload):
    del get_cve(sample_payload)["metrics"]

    assert make_report(sample_payload)["decision"] == "insufficient_data"


def test_empty_metrics(sample_payload):
    get_cve(sample_payload)["metrics"]["cvssMetricV31"] = []

    assert make_report(sample_payload)["decision"] == "insufficient_data"


def test_missing_impact(sample_payload):
    del get_cvss(sample_payload)["confidentialityImpact"]

    report = make_report(sample_payload)

    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None


@pytest.mark.parametrize(
    "impact",
    [None, True, 123, "INVALID", "high", [], {}],
)
def test_invalid_impact(sample_payload, impact):
    get_cvss(sample_payload)["confidentialityImpact"] = impact

    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize(
    "score",
    [-1, 10.1, "9.8", True, None, float("nan"), float("inf")],
)
def test_invalid_score(sample_payload, score):
    get_cvss(sample_payload)["baseScore"] = score

    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": [None]},
        {"vulnerabilities": [{}, {}]},
    ],
)
def test_invalid_structure(payload):
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_wrong_cve_id(sample_payload):
    get_cve(sample_payload)["id"] = "CVE-2099-99999"

    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_invalid_metrics(sample_payload):
    get_cve(sample_payload)["metrics"] = None

    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_invalid_version(sample_payload):
    get_cvss(sample_payload)["version"] = "4.0"

    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_primary_priority(sample_payload):
    metrics = get_cve(sample_payload)["metrics"]["cvssMetricV31"]

    secondary = deepcopy(metrics[0])
    secondary["type"] = "Secondary"
    secondary["source"] = "secondary@example.invalid"
    secondary["cvssData"]["baseScore"] = 5.0

    metrics.insert(0, secondary)

    report = make_report(sample_payload)

    assert report["score"] == 9.8
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "review"


def test_first_metric_without_primary(sample_payload):
    metrics = get_cve(sample_payload)["metrics"]["cvssMetricV31"]
    metrics[0]["type"] = "Secondary"

    second = deepcopy(metrics[0])
    second["cvssData"]["baseScore"] = 5.0
    metrics.append(second)

    assert make_report(sample_payload)["score"] == 9.8


def test_payload_not_modified(sample_payload):
    original = deepcopy(sample_payload)

    make_report(sample_payload)

    assert sample_payload == original
