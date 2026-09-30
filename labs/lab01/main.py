"""Головний модуль запуску Лабораторної роботи №1."""

import sys
from pathlib import Path

# Додаємо корінь проєкту для імпорту спільних модулів
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3
from shared.student import STUDENT_NAME, VARIANT_NUMBER


def main():
    """Точка входу для виконання всіх завдань лабораторної."""
    print("=" * 70)
    print("НАЦІОНАЛЬНИЙ УНІВЕРСИТЕТ «ЛЬВІВСЬКА ПОЛІТЕХНІКА»")
    print(f"Лабораторна робота №1 | Варіант: {VARIANT_NUMBER}")
    print(f"Студент: {STUDENT_NAME} (група КБ-201)")
    print("=" * 70)

    print("\n>>> Запуск Завдання 1 (Аналізатор паролів)...")
    run_task1()

    print("\n\n>>> Запуск Завдання 2 (Контроль доступу)...")
    run_task2()

    print("\n\n>>> Запуск Завдання 3 (Хешування та логування)...")
    run_task3()


if __name__ == "__main__":
    main()
