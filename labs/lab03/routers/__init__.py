"""Переклад помилок БД на безпечні HTTP-відповіді."""

import logging
import sqlite3
from collections.abc import Callable
from typing import Any, TypeVar

from fastapi import HTTPException

from ..repository import ConflictError, NotFoundError

T = TypeVar("T")
logger = logging.getLogger(__name__)


def db_call(operation: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Викликати SQL-операцію та перетворити помилки на HTTP-коди."""
    try:
        return operation(*args, **kwargs)
    except NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ConflictError, sqlite3.IntegrityError) as exc:
        raise HTTPException(
            status_code=409, detail="Конфлікт даних або обмежень бази"
        ) from exc
    except sqlite3.Error as exc:
        logger.exception("Неочікувана помилка SQLite")
        raise HTTPException(
            status_code=500, detail="Внутрішня помилка бази даних"
        ) from exc
