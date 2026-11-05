"""HTTP-маршрути категорій."""

from typing import Annotated

from fastapi import APIRouter, Path, status

from .. import repository
from ..schemas import CategoryCreate, CategoryRead
from . import db_call

router = APIRouter(prefix="/categories", tags=["Категорії"])


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[CategoryRead]:
    """Вивести категорії в порядку зростання id."""
    return db_call(repository.get_categories)


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Назва категорії вже існує"}},
)
def create_category(category: CategoryCreate) -> CategoryRead:
    """Створити нову категорію."""
    return db_call(repository.create_category, category)


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія не порожня"},
    },
)
def delete_category(
    category_id: Annotated[int, Path(gt=0, description="ID категорії")],
) -> None:
    """Видалити категорію, якщо вона не має записів."""
    db_call(repository.delete_category, category_id)
