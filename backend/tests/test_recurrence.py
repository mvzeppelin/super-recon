from datetime import datetime, timezone

import pytest

from app import recurrence


def _dt(*args):
    return datetime(*args, tzinfo=timezone.utc)


# 2026-07-10 é uma sexta-feira (weekday()=4).


def test_daily_later_today():
    now = _dt(2026, 7, 10, 8, 0)
    assert recurrence.compute_next_run("daily", "14:00", now=now) == _dt(2026, 7, 10, 14, 0)


def test_daily_already_passed_today_rolls_to_tomorrow():
    now = _dt(2026, 7, 10, 20, 0)
    assert recurrence.compute_next_run("daily", "14:00", now=now) == _dt(2026, 7, 11, 14, 0)


def test_daily_exact_boundary_is_not_in_the_past():
    now = _dt(2026, 7, 10, 14, 0)
    assert recurrence.compute_next_run("daily", "14:00", now=now) == _dt(2026, 7, 10, 14, 0)


def test_weekly_same_weekday_later_today():
    now = _dt(2026, 7, 10, 8, 0)  # sexta
    assert recurrence.compute_next_run("weekly", "14:00", weekday=4, now=now) == _dt(2026, 7, 10, 14, 0)


def test_weekly_same_weekday_already_passed_rolls_to_next_week():
    now = _dt(2026, 7, 10, 20, 0)  # sexta, já passou das 14h
    assert recurrence.compute_next_run("weekly", "14:00", weekday=4, now=now) == _dt(2026, 7, 17, 14, 0)


def test_weekly_different_weekday():
    now = _dt(2026, 7, 10, 8, 0)  # sexta
    # segunda (weekday=0) seguinte
    assert recurrence.compute_next_run("weekly", "09:00", weekday=0, now=now) == _dt(2026, 7, 13, 9, 0)


def test_monthly_normal_day_later_this_month():
    now = _dt(2026, 7, 1, 0, 0)
    assert recurrence.compute_next_run("monthly", "10:00", day_of_month=15, now=now) == _dt(2026, 7, 15, 10, 0)


def test_monthly_day_already_passed_rolls_to_next_month():
    now = _dt(2026, 7, 20, 0, 0)
    assert recurrence.compute_next_run("monthly", "10:00", day_of_month=15, now=now) == _dt(2026, 8, 15, 10, 0)


def test_monthly_clamps_to_last_day_of_shorter_month():
    # dia 31 configurado, mas fevereiro/2027 (não bissexto) só tem 28 dias.
    now = _dt(2027, 2, 1, 0, 0)
    assert recurrence.compute_next_run("monthly", "10:00", day_of_month=31, now=now) == _dt(2027, 2, 28, 10, 0)


def test_monthly_clamped_but_already_passed_rolls_to_next_month_uncapped():
    # em fevereiro (clampado pro dia 28) já passou; março tem dia 31 de verdade.
    now = _dt(2027, 2, 28, 20, 0)
    assert recurrence.compute_next_run("monthly", "10:00", day_of_month=31, now=now) == _dt(2027, 3, 31, 10, 0)


def test_monthly_december_wraps_year():
    now = _dt(2026, 12, 20, 0, 0)
    assert recurrence.compute_next_run("monthly", "10:00", day_of_month=5, now=now) == _dt(2027, 1, 5, 10, 0)


def test_unknown_periodicity_raises():
    with pytest.raises(ValueError):
        recurrence.compute_next_run("yearly", "10:00", now=_dt(2026, 7, 10, 0, 0))
