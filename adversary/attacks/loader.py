"""Load attack suites from YAML into :class:`Attack` objects."""

from __future__ import annotations

import pathlib
from typing import Any

import yaml

from ..models import Attack, Category, Severity

SUITES_DIR = pathlib.Path(__file__).parent / "suites"


def _coerce_attack(raw: dict[str, Any], suite_name: str, index: int) -> Attack:
    """Turn one YAML mapping into an :class:`Attack`, validating enums."""

    try:
        category = Category(raw["category"])
    except (KeyError, ValueError) as exc:
        raise ValueError(
            f"{suite_name}[{index}]: bad or missing 'category' ({exc})"
        ) from exc
    try:
        severity = Severity[raw.get("severity", "MEDIUM").upper()]
    except KeyError as exc:
        raise ValueError(
            f"{suite_name}[{index}]: unknown severity {raw.get('severity')!r}"
        ) from exc

    attack_id = raw.get("id") or f"{suite_name}-{index:03d}"
    if "payload" not in raw:
        raise ValueError(f"{suite_name}[{index}]: missing 'payload'")

    return Attack(
        id=attack_id,
        category=category,
        severity=severity,
        payload=raw["payload"],
        description=raw.get("description", ""),
        injected_tool_output=raw.get("injected_tool_output"),
        tags={str(k): str(v) for k, v in raw.get("tags", {}).items()},
    )


def load_suite(path: str | pathlib.Path) -> list[Attack]:
    """Load a single suite file into a list of attacks."""

    path = pathlib.Path(path)
    with path.open(encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    suite_name = doc.get("name", path.stem)
    raw_attacks = doc.get("attacks", [])
    if not isinstance(raw_attacks, list):
        raise ValueError(f"{path}: 'attacks' must be a list")
    return [_coerce_attack(a, suite_name, i) for i, a in enumerate(raw_attacks)]


def load_all_suites(directory: str | pathlib.Path = SUITES_DIR) -> list[Attack]:
    """Load and concatenate every ``*.yaml`` suite in a directory."""

    directory = pathlib.Path(directory)
    attacks: list[Attack] = []
    for path in sorted(directory.glob("*.yaml")):
        attacks.extend(load_suite(path))
    if not attacks:
        raise ValueError(f"No attacks found under {directory}")
    return attacks
