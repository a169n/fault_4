import pytest

from fault4.data import (
    DATA_DIR,
    SPEC_PDF,
    fmt_minute,
    load_anomaly_signals,
    load_events,
    parse_event_text,
    sha256_file,
)


def test_load_events_reads_all_ten_rows():
    ev = load_events()
    assert [e.time for e in ev] == ["09:01", "09:03", "09:04", "09:07", "09:08", "09:10", "09:12", "09:13", "09:15", "09:18"]
    assert ev[0].minute == 541 and ev[0].source == "10.20.4.15" and ev[0].severity == "Medium"


def test_parse_thousands_separator():
    assert parse_event_text("1,200 files encrypted") == ("files_encrypted", 1200.0)


def test_parse_percent():
    assert parse_event_text("CPU usage increased to 95%") == ("cpu_usage", 95.0)


def test_parse_kinds_without_value():
    assert parse_event_text("Successful login") == ("login_success", None)
    assert parse_event_text("Antivirus disabled") == ("av_disabled", None)


def test_unknown_event_text_raises():
    with pytest.raises(ValueError, match="Printer jam"):
        parse_event_text("Printer jam")


def test_load_anomaly_signals():
    s = load_anomaly_signals()
    assert [x.name for x in s] == ["Login failures", "File modifications", "CPU usage", "Outbound traffic", "Database requests"]
    assert (s[1].normal, s[1].observed) == (0.12, 0.96)


def test_sha256_and_fmt():
    assert len(sha256_file(DATA_DIR / "incident_events.csv")) == 64 and SPEC_PDF.exists()
    assert fmt_minute(541) == "09:01"
