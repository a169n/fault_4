from fault4.anomaly import anomaly_summary, score_signals, threshold_sensitivity
from fault4.data import AnomalySignal, load_anomaly_signals


def test_all_five_are_anomalies():
    s = anomaly_summary(score_signals(load_anomaly_signals()))
    assert (s["count"], s["total"], s["rate"]) == (5, 5, 1.0)


def test_highest_priority_by_delta_differs_from_ratio():
    s = anomaly_summary(score_signals(load_anomaly_signals()))
    assert s["highest_priority"] == "File modifications" and s["highest_by_ratio"] == "Login failures"


def test_deltas_and_ratios():
    r = {x.name: (x.delta, x.ratio) for x in score_signals(load_anomaly_signals())}
    assert r == {"Login failures": (0.71, 8.1), "File modifications": (0.84, 8.0), "CPU usage": (0.68, 4.4),
                 "Outbound traffic": (0.64, 5.27), "Database requests": (0.73, 5.06)}


def test_threshold_is_inclusive():
    assert score_signals([AnomalySignal("edge", 0.1, 0.75)])[0].is_anomaly is True


def test_threshold_sensitivity():
    assert [d["count"] for d in threshold_sensitivity(load_anomaly_signals())] == [5, 4, 3, 2, 1]


def test_empty_input_and_zero_baseline():
    assert anomaly_summary([])["rate"] == 0.0
    assert score_signals([AnomalySignal("z", 0.0, 0.9)])[0].ratio is None
