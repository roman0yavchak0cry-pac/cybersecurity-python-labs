"""Клієнт для отримання даних із NVD API."""

import os

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def build_headers() -> dict[str, str]:
    """Формування HTTP-заголовків."""
    headers = {"Accept": "application/json"}

    api_key = os.getenv("NVD_API_KEY", "").strip()

    if api_key:
        headers["apiKey"] = api_key

    return headers


def fetch_response(cve_id: str) -> object:
    """Отримання JSON-відповіді NVD за ідентифікатором CVE."""
    try:
        response = requests.get(
            NVD_URL,
            params={"cveId": cve_id},
            headers=build_headers(),
            timeout=(3.05, 10),
            allow_redirects=False,
        )
    except requests.exceptions.Timeout:
        raise ValueError("Перевищено час очікування NVD API.") from None
    except requests.exceptions.ConnectionError:
        raise ValueError("Помилка з'єднання з NVD API.") from None
    except requests.exceptions.RequestException:
        raise ValueError("Помилка мережевого запиту.") from None

    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        raise ValueError(f"HTTP-помилка: {response.status_code}.") from None

    if response.status_code != 200:
        raise ValueError(f"Неочікуваний HTTP-статус: {response.status_code}.")

    try:
        return response.json()
    except ValueError:
        raise ValueError("Некоректна JSON-відповідь NVD.") from None
