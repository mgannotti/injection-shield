"""Shapes that Scout's automation APIs actually return.

``m_list_automations`` reports ``schedule`` as a natural-language string, but
``m_get_automation`` returns it as an object::

    {"kind": "single", "naturalLanguage": "every weekday at 7:00am",
     "days": [1,2,3,4,5], "time": {"hour": 7, "minute": 0}, "hour": 7, "minute": 0}

A detector that assumes the string form stringifies the dict and then reports a
perfectly valid schedule as unrecognized. Normalizing here keeps both engines
honest about the evidence they were actually given.
"""

from __future__ import annotations

from typing import Any

__all__ = ["describe_schedule"]

_DAY_NAMES = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")


def _from_parts(schedule: dict[str, Any]) -> str | None:
    """Reconstruct a cadence phrase when ``naturalLanguage`` is absent."""
    hour, minute = schedule.get("hour"), schedule.get("minute")
    time = schedule.get("time")
    if hour is None and isinstance(time, dict):
        hour, minute = time.get("hour"), time.get("minute")
    if hour is None:
        return None
    clock = f"{int(hour):02d}:{int(minute or 0):02d}"

    days = schedule.get("days")
    if isinstance(days, list) and days:
        indexes = [d for d in days if isinstance(d, int) and 0 <= d < 7]
        if len(indexes) == 7:
            return f"every day at {clock}"
        if sorted(indexes) == [1, 2, 3, 4, 5]:
            return f"every weekday at {clock}"
        if indexes:
            named = ", ".join(_DAY_NAMES[i] for i in sorted(indexes))
            return f"every {named} at {clock}"
    return f"every day at {clock}"


def describe_schedule(schedule: Any) -> str | None:
    """Return a human cadence phrase for either schedule shape, or None if absent.

    Accepts the plain string form, the object form, or nothing at all.
    """
    if schedule is None:
        return None
    if isinstance(schedule, str):
        return schedule.strip() or None
    if isinstance(schedule, dict):
        natural = schedule.get("naturalLanguage")
        if isinstance(natural, str) and natural.strip():
            return natural.strip()
        return _from_parts(schedule)
    return None
