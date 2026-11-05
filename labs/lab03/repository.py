"""Параметризовані SQL-операції, JOIN і атомарні транзакції."""

import sqlite3
from contextlib import closing
from typing import Any

from .database import get_connection
from .schemas import CategoryCreate, RecordCreate, RecordReplace, Status


class NotFoundError(Exception):
    """Запис або категорію не знайдено."""


class ConflictError(Exception):
    """Порушення унікальності або заборонене видалення."""


RECORD_COLUMNS = """
    r.id, r.code, r.title, r.category_id,
    r.value, r.status, c.name AS category_name
"""
RECORD_JOIN = "FROM records AS r JOIN categories AS c ON c.id = r.category_id"


def _read_record(connection: sqlite3.Connection, record_id: int) -> dict[str, Any]:
    """Прочитати запис разом із категорією в поточному з'єднанні."""
    row = connection.execute(
        f"SELECT {RECORD_COLUMNS} {RECORD_JOIN} WHERE r.id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено")
    return dict(row)


def _check_category(connection: sqlite3.Connection, category_id: int) -> None:
    """Переконатися, що категорія існує."""
    found = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if found is None:
        raise NotFoundError("Категорію не знайдено")


def _record_values(record: RecordCreate | RecordReplace) -> tuple[Any, ...]:
    """Параметри для INSERT і UPDATE в узгодженому порядку."""
    return (
        record.code,
        record.title,
        record.category_id,
        record.value,
        record.status,
    )


def get_categories() -> list[dict[str, Any]]:
    """Повернути категорії за зростанням id."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id"
        ).fetchall()
        return [dict(row) for row in rows]


def create_category(category: CategoryCreate) -> dict[str, Any]:
    """Створити категорію з автоматичним id."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute(
            "INSERT INTO categories (name) VALUES (?)", (category.name,)
        )
        return {"id": cursor.lastrowid, "name": category.name}


def delete_category(category_id: int) -> None:
    """Видалити лише порожню наявну категорію."""
    with closing(get_connection()) as connection, connection:
        found = connection.execute(
            "SELECT 1 FROM categories WHERE id = ?", (category_id,)
        ).fetchone()
        if found is None:
            raise NotFoundError("Категорію не знайдено")
        linked = connection.execute(
            "SELECT 1 FROM records WHERE category_id = ? LIMIT 1",
            (category_id,),
        ).fetchone()
        if linked:
            raise ConflictError("Категорія містить записи")
        connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))


def create_record(record: RecordCreate) -> dict[str, Any]:
    """Додати запис і повернути його з назвою категорії."""
    with closing(get_connection()) as connection, connection:
        _check_category(connection, record.category_id)
        cursor = connection.execute(
            """INSERT INTO records
                   (code, title, category_id, value, status)
                   VALUES (?, ?, ?, ?, ?)""",
            _record_values(record),
        )
        return _read_record(connection, cursor.lastrowid)


def get_record(record_id: int) -> dict[str, Any]:
    """Прочитати один запис за id."""
    with closing(get_connection()) as connection:
        return _read_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: Status | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Повернути записи з AND-фільтрами, сортуванням і сторінками."""
    conditions: list[str] = []
    params: list[Any] = []
    if category_id is not None:
        conditions.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        conditions.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        conditions.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        conditions.append("instr(r.title, ?) > 0")
        params.append(q)
    sql = f"SELECT {RECORD_COLUMNS} {RECORD_JOIN}"
    if conditions:
        sql += " WHERE " + " AND ".join(conditions)
    sql += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    params.extend((limit, offset))
    with closing(get_connection()) as connection:
        rows = connection.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def replace_record(record_id: int, record: RecordReplace) -> dict[str, Any]:
    """Повністю змінити п'ять полів без зміни id."""
    with closing(get_connection()) as connection, connection:
        _read_record(connection, record_id)
        _check_category(connection, record.category_id)
        connection.execute(
            """UPDATE records SET code = ?, title = ?,
                   category_id = ?, value = ?, status = ? WHERE id = ?""",
            (*_record_values(record), record_id),
        )
        return _read_record(connection, record_id)


def delete_record(record_id: int) -> None:
    """Видалити запис і повернути 404-виняток, якщо його немає."""
    with closing(get_connection()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(records: list[RecordCreate]) -> list[dict[str, Any]]:
    """Додати весь пакет в одній транзакції або скасувати його."""
    with closing(get_connection()) as connection, connection:
        ids: list[int] = []
        for record in records:
            _check_category(connection, record.category_id)
            cursor = connection.execute(
                """INSERT INTO records
                       (code, title, category_id, value, status)
                       VALUES (?, ?, ?, ?, ?)""",
                _record_values(record),
            )
            ids.append(cursor.lastrowid)
        return [_read_record(connection, record_id) for record_id in ids]
