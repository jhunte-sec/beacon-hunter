"""Time helpers shared by the readers, the scorer and the reports."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

_OFFSET = re.compile(r"([+-]\d{2}):?(\d{2})$")
_FRACTION = re.compile(r"\.(\d+)")


def human_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def iso(ts: float) -> str:
    return datetime.fromtimestamp(round(ts), tz=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value) -> Optional[float]:
    """Seconds since the epoch from the timestamp styles security tools write.

    Handles epoch numbers (seconds, or milliseconds/microseconds if they're too
    big to be seconds), ISO 8601 with "Z", "+00:00" or "+0000" offsets, a space
    instead of "T", slashes in the date (Palo Alto), and any number of fractional
    digits (Suricata writes six, Sysmon three, some tools nine). A time with no
    offset is taken as UTC, which is what Zeek, Suricata and Sysmon's UtcTime use.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return _from_epoch(float(value))
    text = str(value).strip()
    try:
        return _from_epoch(float(text))
    except ValueError:
        pass
    text = text.replace("Z", "+00:00").replace("z", "+00:00")
    if len(text) >= 10 and text[4] == "/" and text[7] == "/":
        text = text[:10].replace("/", "-") + text[10:]
    text = _OFFSET.sub(r"\1:\2", text) if re.search(r"\d{2}:\d{2}:\d{2}", text) else text
    text = _FRACTION.sub(lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _from_epoch(number: float) -> float:
    if number > 1e14:       # microseconds
        return number / 1e6
    if number > 1e11:       # milliseconds
        return number / 1e3
    return number
