import re
from typing import Iterable


SPECIAL_CHAR_PATTERN = re.compile(r"[^a-zA-Z0-9\s@._:/-]+")
MULTISPACE_PATTERN = re.compile(r"\s+")


def clean_text(value: object) -> str:
    text = str(value or "").lower()
    text = SPECIAL_CHAR_PATTERN.sub(" ", text)
    text = MULTISPACE_PATTERN.sub(" ", text)
    return text.strip()


def normalize_texts(values: Iterable[object]) -> list[str]:
    return [clean_text(value) for value in values]


def humanize_feature_name(name: str) -> str:
    feature = re.sub(r"^android\.permission\.", "", name)
    feature = feature.replace("Ljava/lang/", "")
    feature = feature.replace("Landroid/", "")
    feature = feature.replace("Lorg/apache/", "")
    feature = feature.replace("->", " ")
    feature = feature.replace("/", " ")
    feature = feature.replace(".", " ")
    feature = feature.replace("_", " ")
    feature = MULTISPACE_PATTERN.sub(" ", feature)
    return feature.strip().lower()
