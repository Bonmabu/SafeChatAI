KILL_CHAIN = {
    "Phishing": {
        "stage": "Initial Access",
        "next": "Credential Access"
    },

    "Malware": {
        "stage": "Execution",
        "next": "Persistence"
    },

    "Fraud": {
        "stage": "Credential Access",
        "next": "Privilege Escalation"
    },

    "Harassment": {
        "stage": "Impact",
        "next": "Collection"
    },

    "Safe": {
        "stage": "None",
        "next": None
    }
}


def analyze_kill_chain(category):

    return KILL_CHAIN.get(
        category,
        KILL_CHAIN["Safe"]
    )