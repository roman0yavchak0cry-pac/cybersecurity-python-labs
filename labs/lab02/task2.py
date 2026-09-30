from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Створення виділеного логера модуля замість root logger (правило LOG015)
logger = logging.getLogger(__name__)

IPV4_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
DOMAIN_PATTERN: re.Pattern[str] = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


@dataclass(frozen=True)
class ScanResult:
    """Результат аудиту доступності мережевого вузла."""

    host: str
    port: int
    service: str
    status: str
    response_time: str
    notes: str


def validate_host(host: str) -> bool:
    """Перевірка коректності IP-адреси або імені домену."""
    return bool(IPV4_PATTERN.match(host) or DOMAIN_PATTERN.match(host))


def probe_service(host: str, port: int, timeout: float) -> tuple[str, str, str]:
    """Перевірка доступності порту через TCP-з'єднання."""
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((host, port))
        elapsed = (time.perf_counter() - start_time) * 1000
        return "ONLINE", f"{elapsed:.1f} ms", "OK"
    except TimeoutError:
        return "OFFLINE", "TIMEOUT", "Connection timed out"
    except ConnectionRefusedError:
        return "OFFLINE", "REFUSED", "Port is closed / connection refused"
    except OSError as err:
        return "OFFLINE", "ERROR", f"Network error: {err}"
    finally:
        sock.close()


def load_targets(filepath: Path) -> list[dict[str, Any]]:
    """Зчитування списку цілей із файлу JSON або CSV."""
    if not filepath.exists():
        raise FileNotFoundError(f"Файл конфігурації цілей не знайдено: {filepath}")

    if filepath.suffix.lower() == ".json":
        with filepath.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                # Використання TypeError замість ValueError (правило TRY004)
                raise TypeError("JSON має містити кореневий масив об'єктів.")
            return data

    if filepath.suffix.lower() == ".csv":
        with filepath.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return [
                {
                    "host": row["host"],
                    "port": int(row["port"]),
                    "service": row.get("service", "UNKNOWN"),
                }
                for row in reader
            ]

    raise ValueError(f"Непідтримуваний формат файлу: {filepath.suffix}")


def export_csv(results: list[ScanResult], output_path: Path) -> None:
    """Збереження результатів сканування у CSV-файл."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Service", "Status", "ResponseTime", "Notes"])
        for r in results:
            writer.writerow(
                [r.host, r.port, r.service, r.status, r.response_time, r.notes]
            )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CLI-утиліта аудиту доступності мережевих сервісів та портів (Варіант 5)"
    )
    parser.add_argument(
        "--targets",
        type=Path,
        required=True,
        help="Шлях до файлу зі списком вузлів (JSON або CSV)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Таймаут очікування відповіді у секундах (за замовчуванням: 2.0)",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("labs/lab02/data/scan_results.csv"),
        help="Шлях для збереження підсумкового CSV-звіту",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Увімкнути розширене логування рівня DEBUG",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(levelname)s] %(message)s",
    )

    logger.info(
        "Starting service availability scan from target list %s...", args.targets
    )

    try:
        raw_targets = load_targets(args.targets)
    except (json.JSONDecodeError, csv.Error, OSError, TypeError, ValueError) as err:
        # Уникнення перехоплення сліпого винятку Exception (правило BLE001)
        logger.error("Помилка завантаження файлу цілей: %s", err)
        sys.exit(1)

    results: list[ScanResult] = []

    print(
        f"{'Target Host':<16} {'Port':<6} {'Service':<8} "
        f"{'Status':<8} {'Response Time':<14} Notes"
    )
    print("-" * 65)

    for item in raw_targets:
        host = str(item.get("host", "")).strip()
        port = int(item.get("port", 0))
        service = str(item.get("service", "UNKNOWN")).strip()

        if not validate_host(host):
            logger.warning("Невалідний синтаксис хоста: %s. Пропуск.", host)
            continue

        status, resp_time, notes = probe_service(host, port, args.timeout)
        result = ScanResult(
            host=host,
            port=port,
            service=service,
            status=status,
            response_time=resp_time,
            notes=notes,
        )
        results.append(result)

        print(
            f"{result.host:<16} {result.port:<6} {result.service:<8} "
            f"{result.status:<8} {result.response_time:<14} {result.notes}"
        )

    total = len(results)
    online_count = sum(1 for r in results if r.status == "ONLINE")
    offline_count = total - online_count

    online_pct = (online_count / total * 100) if total > 0 else 0.0
    offline_pct = (offline_count / total * 100) if total > 0 else 0.0

    print("\n=== Scan Statistics ===")
    print(f"Total Scanned : {total}")
    print(f"Online        : {online_count} ({online_pct:.1f}%)")
    print(f"Offline       : {offline_count} ({offline_pct:.1f}%)\n")

    try:
        export_csv(results, args.out_csv)
        logger.info("Detailed scan report saved to %s", args.out_csv)
    except OSError as err:
        logger.error("Не вдалося зберегти звіт у CSV: %s", err)


if __name__ == "__main__":
    main()
