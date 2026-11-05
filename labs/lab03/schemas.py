"""Валідація вхідних даних і моделі відповідей Pydantic 2."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]
ValueType = Annotated[int, Field(strict=True, ge=0)]


class StrictModel(BaseModel):
    """Відхиляти невідомі поля та обрізати крайні пробіли."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class CategoryCreate(StrictModel):
    """Новий запис категорії без ручного id."""

    name: str = Field(min_length=2, max_length=40)


class CategoryRead(CategoryCreate):
    """Категорія з її ідентифікатором."""

    id: int


class RecordCreate(StrictModel):
    """П'ять змінюваних полів нового запису."""

    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: ValueType
    status: Status


class RecordReplace(RecordCreate):
    """Повна заміна — обов'язкові всі п'ять полів."""


class RecordRead(RecordCreate):
    """Дані, що повертаються з JOIN із назвою категорії."""

    id: int
    category_name: str


class StudentRead(BaseModel):
    """Обов'язкові ключі для GET /student."""

    student_name: str
    group_name: str
    variant_number: int


class PingRead(BaseModel):
    """Результат GET /ping."""

    status: Literal["ok"]
