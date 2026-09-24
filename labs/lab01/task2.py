"""Завдання 2: Система контролю доступу до ресурсів"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from shared.student import STUDENT_NAME, VARIANT_NUMBER


def check_access(username, resource, users_dict, blocked_set):
    """Перевірка доступу за правилами безпеки."""
    user = users_dict.get(username)
    _, res_level = resource

    # Перевірка існування
    if user is None:
        return False, "User not found"

    # Перевірка на бан
    if username in blocked_set:
        return False, "User is blocked"

    # Перевірка активності
    if not user.get("active", False):
        return False, "Account inactive"

    # Порівняння рівня допуску
    if user.get("clearance", 0) >= res_level:
        return True, ""

    return False, "Insufficient clearance"


def run_task2():
    users = {
        "forensic_lead": {
            "role": "forensic_analyst",
            "clearance": 4,
            "department": "Forensics",
            "active": True,
        },
        "compliance_off": {
            "role": "compliance_officer",
            "clearance": 3,
            "department": "Compliance",
            "active": True,
        },
        "trainee_sec": {
            "role": "trainee",
            "clearance": 1,
            "department": "Training",
            "active": True,
        },
        "vendor_tech": {
            "role": "vendor_support",
            "clearance": 2,
            "department": "Vendor",
            "active": True,
        },
        "archived_usr": {
            "role": "archived",
            "clearance": 1,
            "department": "Archive",
            "active": False,
        },
    }

    resources = [
        ("forensic_images", 4),
        ("compliance_reports", 3),
        ("training_videos", 1),
        ("vendor_tools", 2),
        ("evidence_locker", 4),
        ("certification_docs", 1),
        ("audit_findings", 3),
        ("chain_of_custody", 4),
        ("support_tickets", 2),
        ("learning_modules", 1),
    ]

    security_levels = ("Basic", "Standard", "Protected", "Maximum")
    blocked_users = {"archived_usr", "terminated_vendor", "security_breach"}

    print("=" * 65)
    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}")
    print("ЗАВДАННЯ 2: Система контролю доступу")
    print("=" * 65)

    print("\nРесурси системи:")
    for name, lvl in resources:
        lvl_name = security_levels[lvl - 1]
        print(f" - {name:<22} : Рівень {lvl} ({lvl_name})")

    print("\nРезультати перевірки доступу:")
    print("-" * 65)

    # Список користувачів для перевірки + один сторонній
    test_users = list(users.keys()) + ["hacker"]

    for user in test_users:
        for res in resources:
            res_name, _ = res
            allowed, reason = check_access(user, res, users, blocked_users)
            res_text = "ALLOW" if allowed else f"DENY ({reason})"
            print(f"user={user:<16} resource={res_name:<20} -> {res_text}")


if __name__ == "__main__":
    run_task2()