"""Завдання 3: Хешування паролів, збереження у CSV та логи у JSON."""

import csv
import functools
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from shared.student import STUDENT_NAME, VARIANT_NUMBER

DATA_DIR = Path(__file__).resolve().parent / "data"
CSV_PATH = DATA_DIR / "users.csv"
JSON_PATH = DATA_DIR / "log.json"

MIN_LENGTH = 16
SALT = f"{VARIANT_NUMBER:05d}"


class ValidationError(Exception):
    """Помилка валідації довжини пароля."""


def generate_hash(password, salt="00000"):
    """Рахує sha3_256 хеш від пароля із сіллю."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")

    if len(password) < MIN_LENGTH:
        raise ValidationError(f"Пароль має бути від {MIN_LENGTH} символів")

    combined = f"{password}{salt}".encode()
    return hashlib.sha3_256(combined).hexdigest()


def log_event(func):
    """Декоратор для запису спроб входу в файл log.json."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        username = (
            args[0]
            if args
            else kwargs.get("username", "unknown")
        )
        status = "failure"

        try:
            res = func(*args, **kwargs)
            if res:
                status = "success"
            return res
        finally:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            log_entry = {
                "event": "login",
                "user": str(username),
                "result": status,
                "timestamp": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "args": [str(a) for a in args],
                "kwargs": {k: str(v) for k, v in kwargs.items()},
            }

            logs = []
            if JSON_PATH.exists():
                try:
                    with JSON_PATH.open("r", encoding="utf-8") as f:
                        logs = json.load(f)
                except (json.JSONDecodeError, OSError):
                    logs = []

            logs.append(log_entry)
            with JSON_PATH.open("w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username, password):
    """Валідує дані та створює запис користувача."""
    if not username or not str(username).strip():
        raise ValueError("Ім'я користувача (логін) не може бути порожнім")

    pwd_hash = generate_hash(password, SALT)
    return username, pwd_hash


def create_users(users_list):
    """Записує користувачів у CSV, відловлюючи некоректні записи."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with CSV_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["username", "password_hash"])

        for user, pwd in users_list:
            try:
                valid_user, pwd_hash = create_user(user, pwd)
                writer.writerow([valid_user, pwd_hash])
            except (ValueError, ValidationError) as err:
                print(f" [ВІДХИЛЕНО ПРИ РЕЄСТРАЦІЇ] Логін: '{user}' -> {err}")


def read_users_db():
    """Зчитує користувачів із CSV-файлу."""
    if not CSV_PATH.exists():
        raise FileNotFoundError(f"Файл {CSV_PATH} не знайдено")

    db = []
    with CSV_PATH.open("r", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                db.append((row[0], row[1]))
    return db


@log_event
def login(username, password):
    """Автентифікація користувача через хеш."""
    if not username or not password:
        raise ValueError("Потрібно ввести логін та пароль")

    db = dict(read_users_db())
    saved_hash = db.get(username)
    if saved_hash is None:
        return False

    current_hash = generate_hash(password, SALT)
    return current_hash == saved_hash


def run_task3():
    print("=" * 65)
    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}")
    print("ЗАВДАННЯ 3: Хешування, CSV та логи")
    print("=" * 65)

    test_accounts = (
        ("admin_sec", "Extr3meLySecurePassword#2026"),
        ("analyst_01", "ForensicAnalysisKey#991"),
        ("lead_dev", "QuantumSafePostEncrypt#2"),
        ("compliance_mgr", "PolicyRegulationAudit#10"),
        ("incident_cmd", "ThreatResponseTrigger#44"),
        ("vendor_rep", "TemporaryContractAccess!88"),
        ("soc_specialist", "MonitoringAlertQueue#55"),
        ("guest_auditor", "ExternalVerificationKey!33"),
    )

    try:
        print("\nСтворюємо базу у CSV (обробка списку користувачів)...")
        create_users(test_accounts)

        print("\nЗаписи, успішно додані до бази даних:")
        users_db = read_users_db()
        for i, (u, h) in enumerate(users_db, 1):
            print(f"{i:<2} | {u:<16} | {h[:20]}...{h[-8:]}")

        print("\nТестуємо логін:")
        res1 = login("admin_sec", "Extr3meLySecurePassword#2026")
        print(f" - Вхід з правильним паролем: {res1}")

        res2 = login("admin_sec", "WrongPasswordLength#16")
        print(f" - Вхід з помилковим паролем: {res2}")

        res3 = login("unknown_user", "SomeSecretKey#2026")
        print(f" - Вхід невідомого юзера: {res3}")

        print("\nТест винятку валідації (короткий пароль):")
        try:
            login("analyst_01", "123")
        except ValidationError as err:
            print(f" - Перехоплено ValidationError: {err}")

        print("\nТест винятків ValueError (порожні параметри входу):")
        try:
            login("", "Extr3meLySecurePassword#2026")
        except ValueError as err:
            print(f" - Спроба входу без логіна: {err}")

        try:
            login("admin_sec", "")
        except ValueError as err:
            print(f" - Спроба входу без пароля: {err}")

    except (
        FileNotFoundError,
        PermissionError,
        OSError,
        ValidationError,
        ValueError,
    ) as e:
        print(f"Критична помилка: {e}")


if __name__ == "__main__":
    run_task3()