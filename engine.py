from ml_model import predict

def analyze_text(text: str):
    """
    SOC analysis engine - sends text to ML model
    """

    result = predict(text)

    return {
        "status": result["status"],
        "score": result["score"],
        "category": result["category"],
        "explanation": result.get("explanation", "No explanation provided")
    }
def generate_explanation(text, category, score):
    if score > 80:
        return "High confidence malicious pattern detected in message content."
    elif score > 50:
        return "Suspicious pattern detected with moderate risk indicators."
    else:
        return "Low-risk or normal behavior detected."

    explanation = generate_explanation(text, category, score)