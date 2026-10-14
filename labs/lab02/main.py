from __future__ import annotations

import argparse
from pathlib import Path

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount
from labs.lab02.task2 import run_scanner


def run_demo() -> None:
    print("=== Демонстрація Завдання 1: ООП Модель Безпеки ===\n")

    # 1. Створення користувача та валідація email
    print("[1] Створення користувача та валідація email:")
    user = User(username="sec_analyst", email="analyst@corp.ua")
    user.set_password("SecureStudentPass2026!")
    print(f"  Створено: {user}")

    try:
        print("  Спроба встановити некоректний email 'bad_mail@@'...")
        user.email = "bad_mail@@"
    except ValueError as e:
        print(f"  [Валідація спрацювала]: {e}")

    # 2. Наслідування та права Admin
    print("\n[2] Перевірка наслідування та дозволів Admin:")
    admin = Admin(
        username="lead_admin",
        email="root.lead@cyber.ua",
        permissions={"view_logs", "edit_rules"},
    )
    admin.set_password("RootAccessOnly2026#")
    print(f"  Початкові права: {admin}")
    admin.grant_permission("quarantine_host")
    admin.revoke_permission("edit_rules")
    print(f"  Оновлені права:  {admin}")
    print(f"  Чи є дозвіл 'quarantine_host': {admin.has_permission('quarantine_host')}")

    # 3. Аутентифікація, сесії та аудит
    print("\n[3] Тестування UserAccount та AuditLog:")
    audit = AuditLog()
    account = UserAccount(user=user, audit_log=audit)

    print("  Спроба входу з некоректним паролем:")
    res_fail = account.login("sec_analyst", "WrongPassword", "192.168.1.45")
    print(f"  Результат: {res_fail} | Сесія активна: {account.is_authenticated()}")

    print("  Спроба входу з валідним паролем:")
    res_ok = account.login("sec_analyst", "SecureStudentPass2026!", "192.168.1.45")
    print(f"  Результат: {res_ok} | Сесія активна: {account.is_authenticated()}")

    # 4. Імітація закінчення таймауту сесії
    print("\n[4] Перевірка таймауту сесії (імітація зсуву часу):")
    sess = account["session"]
    if sess:
        sess.last_activity = sess.last_activity.replace(year=2020)
    print(f"  Перевірка після застаріння: is_authenticated = {account.is_authenticated()}")

    # 5. Повторний логін та вихід
    account.login("sec_analyst", "SecureStudentPass2026!", "10.0.0.12")
    print(f"  Повторний вхід успішний. is_authenticated: {account.is_authenticated()}")
    account.logout()
    print(f"  Після logout(). is_authenticated: {account.is_authenticated()}")

    # 6. Журнал аудиту
    print("\n[5] Вміст AuditLog:")
    for idx, log in enumerate(audit.show_all(), start=1):
        ts = log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"  {idx}. [{ts}] Користувач: '{log.username}' | Подія: '{log.action}'")

    # 7. Захист через магічні методи
    print("\n[6] Перевірка магічних методів __getitem__ / __setitem__:")
    print(f"  account['user']: {account['user']}")
    try:
        secret = account["__password_hash"]
        print(secret)
    except KeyError as e:
        print(f"  [Захист приватних даних]: Спроба отримати хеш повернула KeyError: {e}")

    print("\n=== Демонстрація успішно завершена ===")


def main() -> None:
    parser = argparse.ArgumentParser(description="Центральна точка входу до Лабораторної роботи №2")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Підкоманда demo (Завдання 1)
    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)")

    # Підкоманда analyze (Завдання 2)
    analyze_parser = subparsers.add_parser("analyze", help="Запустити CLI-утиліту Варіанту №5")
    analyze_parser.add_argument("--targets", type=Path, required=True, help="Шлях до файлу цілей")
    analyze_parser.add_argument("--timeout", type=float, default=2.0, help="Таймаут (сек)")
    analyze_parser.add_argument(
        "--out-csv",
        type=Path,
        default=Path("labs/lab02/data/scan_results.csv"),
        help="Шлях для збереження CSV-звіту",
    )
    analyze_parser.add_argument("--verbose", action="store_true", help="Детальний вивід (DEBUG)")

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        run_scanner(
            targets_path=args.targets,
            timeout=args.timeout,
            out_csv=args.out_csv,
            verbose=args.verbose,
        )


if __name__ == "__main__":
    main()