"""Командний інтерфейс лабораторної роботи №4."""

import argparse
import json
import re
import sys
from pathlib import Path

from labs.lab04 import api_client
from labs.lab04.analysis import build_report, extract_record
from shared.student import VARIANT_NUMBER


def load_response(path: str | Path) -> object:
    """Читання локальної JSON-відповіді NVD."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except UnicodeError:
        raise ValueError("Некоректне кодування файла.") from None
    except json.JSONDecodeError:
        raise ValueError("Некоректний JSON у файлі.") from None
    except OSError:
        raise ValueError("Не вдалося прочитати файл.") from None


def main(argv: list[str] | None = None) -> int:
    """Обробка аргументів, отримання даних і формування звіту."""
    parser = argparse.ArgumentParser(description="Аналіз вразливостей NVD. Варіант №5.")

    parser.add_argument(
        "--cve",
        required=True,
        help="Ідентифікатор CVE",
    )

    parser.add_argument(
        "--input",
        type=Path,
        help="Шлях до локального JSON-файла",
    )

    args = parser.parse_args(argv)

    if not re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", args.cve):
        print(
            "Помилка: некоректний формат CVE.",
            file=sys.stderr,
        )
        return 2

    if type(VARIANT_NUMBER) is not int or not 1 <= VARIANT_NUMBER <= 15:
        print(
            "Помилка: некоректний номер варіанта.",
            file=sys.stderr,
        )
        return 2

    if VARIANT_NUMBER != 5:
        print(
            "Програма реалізована для варіанта №5.",
            file=sys.stderr,
        )
        return 2

    try:
        if args.input is not None:
            payload = load_response(args.input)
        else:
            payload = api_client.fetch_response(args.cve)

        record = extract_record(payload, args.cve)

        report = build_report(
            record,
            args.cve,
            VARIANT_NUMBER,
        )

    except ValueError as error:
        print(f"Помилка: {error}", file=sys.stderr)
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=4))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
