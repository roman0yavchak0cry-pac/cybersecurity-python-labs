"""Одноразове атомарне заповнення SQLite перевіреним JSON."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .config import CATEGORIES, SEED_VALUES, TITLE_PREFIX, VARIANT_NUMBER
from .database import get_connection, initialize_database
from .schemas import RecordCreate

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"
CATEGORY_IDS = (1, 2, 3, 1, 2, 3, 1, 2)
STATUSES = ("new", "in_progress", "done", "new", "done", "in_progress", "done", "new")


class SeedCategory(BaseModel):
    """Категорія для навчального початкового заповнення."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    id: int = Field(gt=0)
    name: str = Field(min_length=2, max_length=40)


class SeedData(BaseModel):
    """Пакет рівно з трьох категорій і восьми записів."""

    model_config = ConfigDict(extra="forbid")
    categories: list[SeedCategory] = Field(min_length=3, max_length=3)
    records: list[RecordCreate] = Field(min_length=8, max_length=8)


def _validate_variant_data(seed: SeedData) -> None:
    """Перевірити навчальні ID, коди, значення, категорії та статуси."""
    expected_categories = list(enumerate(CATEGORIES, start=1))
    if [(cat.id, cat.name) for cat in seed.categories] != expected_categories:
        raise ValueError("Категорії не відповідають вибраному варіанту")
    for number, record in enumerate(seed.records, start=1):
        if (
            record.code != f"V{VARIANT_NUMBER:02d}-{number:02d}"
            or record.title != f"{TITLE_PREFIX} {number:02d}"
            or record.category_id != CATEGORY_IDS[number - 1]
            or record.status != STATUSES[number - 1]
            or record.value != SEED_VALUES[number - 1]
        ):
            raise ValueError(f"Некоректні початкові дані запису №{number}")


def seed_database() -> str:
    """Додати стартові записи або не змінювати непорожню базу."""
    payload = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    seed = SeedData.model_validate(payload)
    _validate_variant_data(seed)
    initialize_database()
    with closing(get_connection()) as connection, connection:
        category_count = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]
        record_count = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        if category_count or record_count:
            return "База вже містить дані. Повторне заповнення пропущено."
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(category.id, category.name) for category in seed.categories],
        )
        connection.executemany(
            """INSERT INTO records
                   (code, title, category_id, value, status)
                   VALUES (?, ?, ?, ?, ?)""",
            [
                (
                    record.code,
                    record.title,
                    record.category_id,
                    record.value,
                    record.status,
                )
                for record in seed.records
            ],
        )
    return "Початкові дані додано: 3 категорії, 8 записів."


if __name__ == "__main__":
    try:
        print(seed_database())
    except (OSError, ValueError, ValidationError, sqlite3.Error) as exc:
        raise SystemExit(f"Помилка початкового заповнення: {exc}") from exc
