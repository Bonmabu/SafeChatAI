from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

texts = [

    # PHISHING
    "your account is suspended click link",
    "verify your password immediately",
    "login now to avoid account closure",
    "security alert verify your identity",

    # SCAM
    "you won a lottery claim now",
    "send money to receive your prize",
    "investment opportunity guaranteed returns",

    # FRAUD
    "bank transfer required urgently",
    "payment failed update card details",
    "confirm your banking credentials",

    # SAFE
    "hello how are you",
    "meeting scheduled tomorrow",
    "lets have lunch",
    "project discussion next week",
    "good morning team"
]

labels = [
    "Phishing",
    "Phishing",
    "Phishing",
    "Phishing",

    "Scam",
    "Scam",
    "Scam",

    "Fraud",
    "Fraud",
    "Fraud",

    "Safe",
    "Safe",
    "Safe",
    "Safe",
    "Safe"
]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

model = LogisticRegression(max_iter=1000)
model.fit(X, labels)


def predict(text: str):

    x = vectorizer.transform([text])

    category = model.predict(x)[0]

    confidence = max(model.predict_proba(x)[0]) * 100

    if category == "Safe":
        status = "Low Risk"

    elif confidence > 80:
        status = "High Risk"

    else:
        status = "Suspicious"

    return {
        "status": status,
        "score": round(confidence, 2),
        "category": category,
        "explanation": f"Detected category: {category}"
    }