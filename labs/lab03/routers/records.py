"""Маршрути CRUD, фільтрів і пакетного додавання записів."""

from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, status

from .. import repository
from ..schemas import RecordCreate, RecordRead, RecordReplace, Status
from . import db_call

router = APIRouter(prefix="/records", tags=["Записи"])

# Варіант 5: value та min_value — невід’ємні цілі числа (events).
MinValueType = Annotated[int | None, Query(ge=0)]


@router.get("", response_model=list[RecordRead], summary="Список і фільтри записів")
def list_records(
    category_id: Annotated[int | None, Query(gt=0)] = None,
    status_filter: Annotated[Status | None, Query(alias="status")] = None,
    min_value: MinValueType = None,
    q: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[RecordRead]:
    """Поєднати фільтри через AND та сортувати записи за id."""
    return db_call(
        repository.list_records,
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Атомарно створити пакет 1–100 записів",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Дублікат коду або конфлікт"},
    },
)
def create_bulk(
    records: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[RecordRead]:
    """Перевірити всю модель і додати пакет однією транзакцією."""
    return db_call(repository.create_records_bulk, records)


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати запис за ID",
    responses={404: {"description": "Запис не знайдено"}},
)
def get_record(
    record_id: Annotated[int, Path(gt=0)],
) -> RecordRead:
    """Отримати один запис разом із назвою категорії."""
    return db_call(repository.get_record, record_id)


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити запис",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Дублікат коду"},
    },
)
def create_record(record: RecordCreate) -> RecordRead:
    """Створити новий запис без передавання id."""
    return db_call(repository.create_record, record)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити поля запису",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Дублікат коду"},
    },
)
def replace_record(
    record_id: Annotated[int, Path(gt=0)],
    record: RecordReplace,
) -> RecordRead:
    """Замінити всі змінювані поля, залишивши id незмінним."""
    return db_call(repository.replace_record, record_id, record)


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити запис",
    responses={404: {"description": "Запис не знайдено"}},
)
def delete_record(record_id: Annotated[int, Path(gt=0)]) -> None:
    """Видалити запис за id."""
    db_call(repository.delete_record, record_id)
