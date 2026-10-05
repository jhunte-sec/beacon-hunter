"""Small formatting helpers shared by the scorer and the reports."""

from datetime import datetime, timezone


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
