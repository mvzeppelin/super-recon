"""Cálculo puro de "próxima execução" para recorrência de scans — sem
nenhuma dependência de OpenSearch/Celery, só datetime/calendar (testável sem
mock). Horário sempre em UTC (ver README "Recorrência de scans")."""
import calendar
from datetime import datetime, timedelta

_MAX_MONTH_ITERATIONS = 24  # teto de segurança — nunca deveria levar tanto


def _parse_run_time(run_time: str) -> tuple[int, int]:
    hour_str, minute_str = run_time.split(":")
    return int(hour_str), int(minute_str)


def compute_next_run(
    periodicity: str,
    run_time: str,
    *,
    weekday: int | None = None,
    day_of_month: int | None = None,
    now: datetime,
) -> datetime:
    """Devolve o próximo datetime (UTC, mesmo tzinfo de `now`) >= `now` que
    bate com a periodicidade configurada."""
    hour, minute = _parse_run_time(run_time)

    if periodicity == "daily":
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate < now:
            candidate += timedelta(days=1)
        return candidate

    if periodicity == "weekly":
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        days_ahead = (weekday - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate < now:
            candidate += timedelta(days=7)
        return candidate

    if periodicity == "monthly":
        year, month = now.year, now.month
        for _ in range(_MAX_MONTH_ITERATIONS):
            last_day = calendar.monthrange(year, month)[1]
            day = min(day_of_month, last_day)
            candidate = now.replace(
                year=year, month=month, day=day, hour=hour, minute=minute, second=0, microsecond=0,
            )
            if candidate >= now:
                return candidate
            month += 1
            if month > 12:
                month = 1
                year += 1
        raise ValueError(f"não foi possível calcular a próxima execução mensal (dia {day_of_month})")

    raise ValueError(f"periodicidade desconhecida: {periodicity!r}")
