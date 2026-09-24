"""Завдання 1: Оцінка стійкості паролів."""

import random
import string
import sys
from pathlib import Path

# Підключаємо корінь проєкту для імпорту спільних даних
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from shared.student import STUDENT_NAME, VARIANT_NUMBER


def check_password_strength(password, min_len, forbidden, all_passwords):
    """Визначає категорію надійності пароля."""
    # Базова перевірка на заборонені значення (Fail-Secure)
    if password in forbidden or len(password) < min_len:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_spec = any(c in string.punctuation for c in password)

    # Якщо виконані обов'язкові критерії варіанта 5
    if has_digit and has_upper and has_spec:
        is_unique = all_passwords.count(password) == 1
        if len(password) >= min_len + 4 and is_unique:
            return "Дуже сильний"
        return "Сильний"

    # Підрахунок груп символів для неповних наборів
    groups = sum((has_digit, has_upper, has_lower, has_spec))
    if groups <= 1:
        return "Слабкий"
    return "Середній"


def run_task1():
    passwords = [
        "DataS3cur3!",
        "123",
        "Crypto@Analysis",
        "test123",
        "Quantum#2023",
        "access",
        "Security@Pro",
        "password1",
        "Adv@nced123",
        "guest123",
        "onlylowercasetext",
        "Super#SecureKey2026!",
    ]

    criteria = {"min_length": 12}
    forbidden_passwords = {
        "123",
        "test123",
        "access",
        "password1",
        "guest123",
        "admin",
    }

    print("=" * 65)
    print(f"Студент: {STUDENT_NAME} | Варіант: {VARIANT_NUMBER}")
    print("ЗАВДАННЯ 1: Аналізатор надійності паролів")
    print("=" * 65)

    # Симуляція повторного використання паролів
    random.seed(42)
    base_len = len(passwords)
    random_indexes = [random.randint(0, base_len - 1) for _ in range(3)]
    for i in random_indexes:
        passwords.append(passwords[i])

    print(f"{'№':<3} | {'Пароль':<22} | {'Довжина':<8} | {'Статус'}")
    print("-" * 58)

    min_length = criteria["min_length"]
    for idx, pwd in enumerate(passwords, start=1):
        status = check_password_strength(
            pwd, min_length, forbidden_passwords, passwords
        )
        print(f"{idx:<3} | {pwd:<22} | {len(pwd):<8} | {status}")


if __name__ == "__main__":
    run_task1()