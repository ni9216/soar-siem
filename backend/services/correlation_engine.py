def correlate(log: str):

    log = log.lower()

    if "scan" in log and "failed login" in log:
        return "Possible Intrusion Attempt"

    if "ransomware" in log and "file encrypted" in log:
        return "Ransomware Attack"

    if "malware" in log and "outbound connection" in log:
        return "Malware Communication"

    return "Generic Security Event"
