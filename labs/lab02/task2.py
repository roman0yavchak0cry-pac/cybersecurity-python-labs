from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import socket
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# Регулярні вирази для перевірки коректності хоста (IP або домен)
IP_REGEX = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
DOMAIN_REGEX = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


@dataclass(frozen=True)
class ScanResult:
    """Незмінний результат сканування порту (DTO)."""

    host: str
    port: int
    service: str
    status: str
    response_time: str
    notes: str


def validate_host(host: str) -> bool:
    """Перевірка валідності хоста (IPv4, FQDN-домен або localhost)."""
    if host.lower() == "localhost":
        return True
    return bool(IP_REGEX.match(host) or DOMAIN_REGEX.match(host))


def check_port(host: str, port: int, timeout: float) -> tuple[str, str, str]:
    """Спроба відкрити TCP-з'єднання на заданий порт з вимірюванням часу."""
    if not (1 <= port <= 65535):
        return "OFFLINE", "INVALID_PORT", f"Port {port} is out of range (1-65535)"

    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        elapsed_ms = (time.perf_counter() - start) * 1000
        return "ONLINE", f"{elapsed_ms:.1f} ms", "OK"
    except TimeoutError:
        return "OFFLINE", "TIMEOUT", "Connection timed out"
    except ConnectionRefusedError:
        return "OFFLINE", "REFUSED", "Port is closed / connection refused"
    except (OSError, OverflowError) as err:
        return "OFFLINE", "ERROR", f"Network error: {err}"
    finally:
        sock.close()


def load_targets(filepath: Path) -> list[dict]:
    """Зчитування списку цілей із файлу JSON або CSV."""
    if not filepath.exists():
        raise FileNotFoundError(f"Файл не знайдено: {filepath}")

    ext = filepath.suffix.lower()

    if ext == ".json":
        with filepath.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, list):
                raise TypeError("JSON файл повинен містити список об'єктів")
            return data

    if ext == ".csv":
        targets: list[dict] = []
        with filepath.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                targets.append(
                    {
                        "host": row["host"],
                        "port": int(row["port"]),
                        "service": row.get("service", "UNKNOWN"),
                    }
                )
        return targets

    raise ValueError(f"Непідтримуваний формат файлу: {ext}")


def save_results_to_csv(results: list[ScanResult], output_path: Path) -> None:
    """Збереження результатів перевірки у файл CSV."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Service", "Status", "ResponseTime", "Notes"])
        for item in results:
            writer.writerow(
                [
                    item.host,
                    item.port,
                    item.service,
                    item.status,
                    item.response_time,
                    item.notes,
                ]
            )


def run_scanner(
    targets_path: Path,
    timeout: float = 2.0,
    out_csv: Path = Path("labs/lab02/data/scan_results.csv"),
    verbose: bool = False,
) -> None:
    """Головна функція запуску сканування та виводу звіту в консоль."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s", force=True)

    logger.info("Starting service availability scan from target list %s...", targets_path)

    try:
        targets = load_targets(targets_path)
    except (json.JSONDecodeError, csv.Error, OSError, TypeError, ValueError) as err:
        logger.error("Помилка читання цілей: %s", err)
        sys.exit(1)

    results: list[ScanResult] = []
    print(f"{'Target Host':<24} {'Port':<6} {'Service':<8} {'Status':<8} {'Response Time':<14} Notes")
    print("-" * 75)

    for item in targets:
        host = str(item.get("host", "")).strip()
        port = int(item.get("port", 0))
        service = str(item.get("service", "UNKNOWN")).strip()

        # Відсіювання невалідних хостів із попередженням у лог
        if not validate_host(host):
            logger.warning("Невалідний хост: %s. Пропускаємо.", host)
            continue

        status, resp_time, notes = check_port(host, port, timeout)
        res = ScanResult(
            host=host,
            port=port,
            service=service,
            status=status,
            response_time=resp_time,
            notes=notes,
        )
        results.append(res)
        print(f"{res.host:<24} {res.port:<6} {res.service:<8} {res.status:<8} {res.response_time:<14} {res.notes}")

    # Підрахунок статистики за допомогою collections.Counter
    total = len(results)
    status_counter = Counter(r.status for r in results)
    online_count = status_counter["ONLINE"]
    offline_count = status_counter["OFFLINE"]

    online_pct = (online_count / total * 100) if total > 0 else 0.0
    offline_pct = (offline_count / total * 100) if total > 0 else 0.0

    print("\n=== Scan Statistics ===")
    print(f"Total Scanned : {total}")
    print(f"Online        : {online_count} ({online_pct:.1f}%)")
    print(f"Offline       : {offline_count} ({offline_pct:.1f}%)\n")

    try:
        save_results_to_csv(results, out_csv)
        logger.info("Detailed scan report saved to %s", out_csv)
    except OSError as err:
        logger.error("Не вдалося зберегти CSV звіт: %s", err)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Сканер доступності мережевих сервісів та перевірка портів (Варіант 5)"
    )
    parser.add_argument(
        "--targets",
        type=Path,
        required=True,
        help="Шлях до файлу цілей (JSON або CSV)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Таймаут TCP з'єднання в секундах (за замовчуванням: 2.0)",
    )
    parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("labs/lab02/data/scan_results.csv"),
        help="Шлях для експорту CSV-звіту",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Детальний режим виводу логів (DEBUG)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_scanner(
        targets_path=args.targets,
        timeout=args.timeout,
        out_csv=args.out_csv,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()