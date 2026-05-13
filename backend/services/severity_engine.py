def severity_score(text: str):

    text = text.lower()

    rules = {
        "ransomware": 10,
        "exploit": 7,
        "brute force": 6,
        "malware": 6,
        "attack": 4,
        "scan": 2,
        "failed login": 5,
        "error": 1
    }

    score = sum(text.count(k) * v for k, v in rules.items())

    if score >= 15:
        return "Critical"

    elif score >= 10:
        return "High"

    elif score >= 5:
        return "Medium"

    return "Low"
