from collections import Counter
from datetime import datetime, timezone


PREDICTION_HISTORY = []


def learn(category, score=0, corr_id=None, timestamp=None):
    """
    Record an observed threat for predictive analysis.

    Backward compatible with the original learn(category) interface.
    """

    try:
        score = float(score or 0)
    except (TypeError, ValueError):
        score = 0.0

    event = {
        "category": str(category or "Unknown"),
        "score": max(0.0, min(100.0, score)),
        "corr_id": corr_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat()
    }

    PREDICTION_HISTORY.append(event)

    if len(PREDICTION_HISTORY) > 500:
        del PREDICTION_HISTORY[:-500]


def _recent_events(limit=50):
    return PREDICTION_HISTORY[-limit:]


def _category_stats(events):
    stats = {}

    for event in events:
        category = event["category"]

        if category not in stats:
            stats[category] = {
                "count": 0,
                "total_score": 0.0,
                "max_score": 0.0
            }

        stats[category]["count"] += 1
        stats[category]["total_score"] += event["score"]
        stats[category]["max_score"] = max(
            stats[category]["max_score"],
            event["score"]
        )

    for category, data in stats.items():
        data["avg_score"] = round(
            data["total_score"] / data["count"],
            2
        )

    return stats


def predict():
    """
    Produce the Phase 34 threat prediction.

    Returns a richer prediction contract while retaining
    next_attack and confidence for backward compatibility.
    """

    if not PREDICTION_HISTORY:
        return {
            "next_attack": "Unknown",
            "prediction": "UNKNOWN",
            "confidence": 0,
            "expected_score": 0,
            "threat_direction": "STABLE",
            "prediction_window": "7+ DAYS",
            "supporting_signals": []
        }

    recent = _recent_events(50)
    stats = _category_stats(recent)

    if not stats:
        return {
            "next_attack": "Unknown",
            "prediction": "UNKNOWN",
            "confidence": 0,
            "expected_score": 0,
            "threat_direction": "STABLE",
            "prediction_window": "7+ DAYS",
            "supporting_signals": []
        }

    total_events = len(recent)

    ranked = []

    for category, data in stats.items():
        frequency_ratio = data["count"] / total_events

        frequency_score = frequency_ratio * 100
        risk_score = data["avg_score"]

        # Recent activity receives additional weight.
        recent_count = sum(
            1
            for event in recent[-10:]
            if event["category"] == category
        )

        recency_score = min(100, recent_count * 10)

        prediction_score = (
            frequency_score * 0.35
            + risk_score * 0.45
            + recency_score * 0.20
        )

        ranked.append({
            "category": category,
            "count": data["count"],
            "avg_score": data["avg_score"],
            "max_score": data["max_score"],
            "prediction_score": round(
                min(100, prediction_score),
                2
            )
        })

    ranked.sort(
        key=lambda item: (
            item["prediction_score"],
            item["count"],
            item["avg_score"]
        ),
        reverse=True
    )

    primary = ranked[0]

    predicted_category = primary["category"]
    expected_score = primary["avg_score"]

    # Confidence reflects both historical frequency
    # and consistency of the predicted threat.
    frequency_confidence = (
        primary["count"] / total_events
    ) * 100

    risk_confidence = min(
        100,
        primary["avg_score"]
    )

    confidence = round(
        (
            frequency_confidence * 0.45
            + risk_confidence * 0.55
        ),
        2
    )

    if expected_score >= 80:
        threat_direction = "ESCALATING"
        prediction_window = "0-24 HOURS"
    elif expected_score >= 60:
        threat_direction = "ELEVATED"
        prediction_window = "1-3 DAYS"
    elif expected_score >= 40:
        threat_direction = "WATCH"
        prediction_window = "3-7 DAYS"
    else:
        threat_direction = "STABLE"
        prediction_window = "7+ DAYS"

    supporting_signals = [
        f"{primary['count']} recent {predicted_category} event(s).",
        f"Historical average risk is {primary['avg_score']}.",
        f"Maximum observed risk is {primary['max_score']}.",
        f"{sum(1 for event in recent[-10:] if event['category'] == predicted_category)} "
        f"{predicted_category} event(s) occurred in the latest 10 observations."
    ]

    return {
        # Backward compatibility
        "next_attack": predicted_category,
        "confidence": confidence,

        # Phase 34 prediction contract
        "prediction": predicted_category,
        "predicted_threat": predicted_category,
        "expected_score": expected_score,
        "threat_direction": threat_direction,
        "prediction_window": prediction_window,

        "historical_count": primary["count"],
        "historical_avg_score": primary["avg_score"],
        "maximum_observed_score": primary["max_score"],

        "candidate_threats": ranked[:10],

        "supporting_signals": supporting_signals,

        "generated": datetime.now(
            timezone.utc
        ).isoformat()
    }


def get_prediction_history():
    """
    Return the retained prediction-learning history.
    """

    return list(PREDICTION_HISTORY)


def clear_prediction_history():
    """
    Clear prediction-learning state.
    Useful for controlled testing.
    """

    PREDICTION_HISTORY.clear()
