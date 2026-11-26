"""Тести HTTP-клієнта без мережевих запитів."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

CVE_ID = "CVE-2099-10001"


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("key", ["", "   "])
def test_empty_key(monkeypatch, key):
    monkeypatch.setenv("NVD_API_KEY", key)

    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-test-key  ")

    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }


def test_successful_request(monkeypatch, sample_payload):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = sample_payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    assert api_client.fetch_response(CVE_ID) == sample_payload

    fake_get.assert_called_once_with(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": CVE_ID},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )

    response.raise_for_status.assert_called_once_with()


def test_request_with_key(monkeypatch, sample_payload):
    monkeypatch.setenv("NVD_API_KEY", "fake-test-key")

    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = sample_payload

    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    api_client.fetch_response(CVE_ID)

    assert fake_get.call_args.kwargs["headers"] == {
        "Accept": "application/json",
        "apiKey": "fake-test-key",
    }


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.Timeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.RequestException,
    ],
)
def test_network_errors(monkeypatch, error):
    fake_get = Mock(side_effect=error)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    with pytest.raises(ValueError):
        api_client.fetch_response(CVE_ID)


@pytest.mark.parametrize("status", [403, 404, 429, 500])
def test_http_errors(monkeypatch, status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=response
    )

    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(return_value=response),
    )

    with pytest.raises(ValueError, match=str(status)):
        api_client.fetch_response(CVE_ID)


@pytest.mark.parametrize("status", [201, 204, 301, 302])
def test_unexpected_status(monkeypatch, status):
    response = Mock(spec=requests.Response)
    response.status_code = status

    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(return_value=response),
    )

    with pytest.raises(ValueError, match=str(status)):
        api_client.fetch_response(CVE_ID)


def test_invalid_json(monkeypatch):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )

    monkeypatch.setattr(
        api_client.requests,
        "get",
        Mock(return_value=response),
    )

    with pytest.raises(ValueError, match="JSON"):
        api_client.fetch_response(CVE_ID)
