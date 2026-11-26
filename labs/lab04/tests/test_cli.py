"""Тести командного інтерфейсу."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from labs.lab04 import main

CVE_ID = "CVE-2099-10001"

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"


def test_local_mode(monkeypatch, capsys):
    fake_fetch = Mock()
    monkeypatch.setattr(
        main.api_client,
        "fetch_response",
        fake_fetch,
    )

    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])

    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 0
    assert report["variant"] == 5
    assert report["score"] == 9.8
    assert report["decision"] == "review"
    assert captured.err == ""

    fake_fetch.assert_not_called()


def test_network_mode(monkeypatch, capsys, sample_payload):
    fake_fetch = Mock(return_value=sample_payload)
    monkeypatch.setattr(
        main.api_client,
        "fetch_response",
        fake_fetch,
    )

    assert main.main(["--cve", CVE_ID]) == 0

    captured = capsys.readouterr()

    assert json.loads(captured.out)["decision"] == "review"
    assert captured.err == ""

    fake_fetch.assert_called_once_with(CVE_ID)


def test_missing_file(tmp_path, capsys):
    missing = tmp_path / "missing.json"

    code = main.main(["--cve", CVE_ID, "--input", str(missing)])

    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert "Помилка" in captured.err


def test_invalid_json_file(tmp_path, capsys):
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{invalid", encoding="utf-8")

    code = main.main(["--cve", CVE_ID, "--input", str(invalid)])

    captured = capsys.readouterr()

    assert code == 1
    assert captured.out == ""
    assert "JSON" in captured.err


@pytest.mark.parametrize(
    "cve_id",
    ["INVALID", "cve-2026-1234", "CVE-26-1234", "CVE-2026-123"],
)
def test_invalid_cve(cve_id, capsys):
    assert main.main(["--cve", cve_id]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "CVE" in captured.err


def test_missing_argument(capsys):
    with pytest.raises(SystemExit) as error:
        main.main([])

    assert error.value.code == 2
    assert "--cve" in capsys.readouterr().err


@pytest.mark.parametrize("variant", [0, 16, True, "5", None])
def test_invalid_variant(monkeypatch, capsys, variant):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)

    assert main.main(["--cve", CVE_ID]) == 2

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "варіанта" in captured.err


def test_not_found(monkeypatch, capsys):
    monkeypatch.setattr(
        main.api_client,
        "fetch_response",
        Mock(return_value={"vulnerabilities": []}),
    )

    assert main.main(["--cve", CVE_ID]) == 0

    report = json.loads(capsys.readouterr().out)

    assert report["decision"] == "not_found"


def test_network_failure(monkeypatch, capsys):
    monkeypatch.setattr(
        main.api_client,
        "fetch_response",
        Mock(side_effect=ValueError("Помилка мережі.")),
    )

    assert main.main(["--cve", CVE_ID]) == 1

    captured = capsys.readouterr()

    assert captured.out == ""
    assert "Помилка" in captured.err
