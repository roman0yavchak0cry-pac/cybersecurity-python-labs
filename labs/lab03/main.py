"""FastAPI-застосунок лабораторної №3."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from shared import student

from .config import DOMAIN, THRESHOLD, UNIT, VARIANT_NUMBER
from .database import initialize_database
from .routers.categories import router as categories_router
from .routers.records import router as records_router
from .schemas import PingRead, StudentRead


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Створити відсутні таблиці лише під час запуску застосунку."""
    initialize_database()
    yield


app = FastAPI(
    title=f"Лабораторна №3 — {DOMAIN}",
    description=(
        f"Навчальний сервіс: {DOMAIN}. "
        f"Одиниця вимірювання: {UNIT}; поріг: {THRESHOLD}. "
        "Значення порога наведено для аналізу, а не для відхилення даних."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories_router)
app.include_router(records_router)


def _student_attribute(*names: str) -> Any:
    """Прочитати названі дані з наявного shared/student.py."""
    for name in names:
        value = getattr(student, name, None)
        if value is not None:
            return value
    for container_name in ("STUDENT", "student", "STUDENT_INFO", "student_info"):
        container = getattr(student, container_name, None)
        if isinstance(container, dict):
            for name in names:
                value = container.get(name)
                if value is not None:
                    return value
    raise RuntimeError(
        "У shared/student.py не знайдено потрібних даних. "
        "Перевірте назви змінних у функції _student_attribute."
    )


@app.get("/ping", response_model=PingRead, tags=["Сервіс"], summary="Перевірка API")
def ping() -> dict[str, str]:
    """Перевірити доступність сервера."""
    return {"status": "ok"}


@app.get(
    "/student",
    response_model=StudentRead,
    tags=["Сервіс"],
    summary="Дані студента",
)
def student_info() -> dict[str, Any]:
    """Отримати ПІБ, групу і варіант зі спільного модуля."""
    name = _student_attribute("student_name", "STUDENT_NAME", "full_name", "FULL_NAME")
    group = _student_attribute("group_name", "GROUP_NAME", "group", "GROUP")
    variant = int(
        _student_attribute("variant_number", "VARIANT_NUMBER", "variant", "VARIANT")
    )
    if variant != VARIANT_NUMBER:
        raise RuntimeError(
            "Номер варіанта у shared/student.py і config.py відрізняється"
        )
    return {
        "student_name": str(name),
        "group_name": str(group),
        "variant_number": variant,
    }
