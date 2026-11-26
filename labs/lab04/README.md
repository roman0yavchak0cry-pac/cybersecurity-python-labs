
# Лабораторна робота №4

## Інтеграція із зовнішніми Web API та автоматизоване тестування Python-коду

- Студент: Явчак Роман Ігорович
- Група: КБ-201
- Варіант: 5

## Індивідуальне завдання

Аналіз вразливостей із високим впливом
на конфіденційність за CVSS v3.1.

Правило відбору:

- threshold: 7.0
- field: confidentialityImpact
- expected: HIGH

Рішення review формується, якщо оцінка
CVSS >= 7.0 та confidentialityImpact == HIGH.

## Встановлення залежностей

Потрібен Python 3.12 або новіший.

```bash
pip install -r requirements.txt
```

## Локальний запуск

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

## Запит до NVD API

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

API-ключ необов'язковий.
За наявності він зчитується зі змінної NVD_API_KEY.

## Формат JSON-звіту

- cve_id — ідентифікатор CVE;
- variant — номер варіанта;
- description — англійський опис;
- vuln_status — статус запису;
- cvss_version — версія CVSS;
- score — базова оцінка;
- score_source — джерело оцінки;
- vector — вектор CVSS;
- rule — правило відбору;
- observed — фактичне значення метрики;
- decision — результат аналізу.

Можливі рішення:

- review;
- other;
- not_found;
- rejected;
- insufficient_data.

## Коди завершення

- 0 — звіт сформовано;
- 1 — помилка отримання або обробки даних;
- 2 — некоректні аргументи або номер варіанта.

## Автоматизоване тестування

```bash
python -m pytest labs/lab04/tests -q
python -m pytest labs/lab04/tests -v
```

Результат: 75 успішних тестів.
Реальні HTTP-запити під час тестування заборонено.

## Перевірка стилю

```bash
ruff check labs/lab04
ruff format --check labs/lab04
```

Результат: усі перевірки успішні.
