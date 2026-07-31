from collections import Counter

PREDICTION_HISTORY = []


def learn(category):

    PREDICTION_HISTORY.append(category)

    if len(PREDICTION_HISTORY) > 500:
        PREDICTION_HISTORY.pop(0)


def predict():

    if not PREDICTION_HISTORY:
        return {
            "next_attack": "Unknown",
            "confidence": 0
        }

    counts = Counter(PREDICTION_HISTORY)

    attack = counts.most_common(1)[0]

    confidence = round(
        attack[1] / len(PREDICTION_HISTORY) * 100,
        2
    )

    return {
        "next_attack": attack[0],
        "confidence": confidence
    }