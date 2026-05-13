def map_to_mitre(log):
    # Simple mapping based on keywords
    log_lower = log.lower()
    if 'ransomware' in log_lower:
        return 'T1486'  # Data Encrypted for Impact
    elif 'malware' in log_lower:
        return 'T1059'  # Command and Scripting Interpreter
    elif 'exploit' in log_lower:
        return 'T1203'  # Exploitation for Client Execution
    elif 'scan' in log_lower:
        return 'T1046'  # Network Service Scanning
    elif 'brute force' in log_lower:
        return 'T1110'  # Brute Force
    else:
        return 'T0000'  # Unknown