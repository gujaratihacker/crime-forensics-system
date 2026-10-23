import re

def analyze_complaint(description, category, financial_loss=0.0):
    """
    Simulated AI analysis of a complaint description and details.
    Uses regex and keyword matching to suggest category, priority,
    missing details, evidence suggestions, and extract suspect indicators.
    """
    desc_lower = description.lower()
    
    # 1. Extract Suspect Indicators
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", description)
    phones = re.findall(r"\+?[0-9]{10,12}", description)
    urls = re.findall(r"https?://[a-zA-Z0-9./_-]+", description)
    
    # UPI IDs are typically user@bank (excluding common email domains to prevent false positives)
    upis_raw = re.findall(r"[a-zA-Z0-9._-]+@[a-zA-Z0-9_-]+", description)
    upis = []
    email_domains = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'rediffmail.com', 'protomail.com', 'email.com', 'forensics.local'}
    for upi in upis_raw:
        domain = upi.split('@')[1].lower()
        if domain not in email_domains:
            upis.append(upi)
            
    # Combine indicators into a list
    indicators = []
    indicators.extend([f"email:{e}" for e in emails])
    indicators.extend([f"phone:{p}" for p in phones])
    indicators.extend([f"url:{u}" for u in urls])
    indicators.extend([f"upi:{u}" for u in upis])
    
    # 2. Priority Scoring
    priority = "LOW"
    priority_reasons = []
    
    # Critical threat indicators
    critical_keywords = ['kill', 'harm', 'suicide', 'stalk', 'threaten', 'extort', 'blackmail', 'death', 'leak photo', 'morph']
    if any(kw in desc_lower for kw in critical_keywords):
        priority = "CRITICAL"
        priority_reasons.append("Safety threat: Keywords relating to physical safety, extortion, or blackmail detected.")
    
    # Financial indicators
    elif financial_loss >= 50000:
        priority = "HIGH"
        priority_reasons.append("High financial loss: Loss is equal to or greater than Rs. 50,000.")
    elif financial_loss > 0 or any(kw in desc_lower for kw in ['loss', 'bank', 'transfer', 'credit card', 'otp']):
        priority = "MEDIUM"
        priority_reasons.append("Financial fraud: Cyber fraud indicators or financial loss reported.")
        
    # Default priority details
    if not priority_reasons:
        priority_reasons.append("Standard priority: No urgent safety threats or high financial values detected.")
        
    # 3. Category Verification
    suggested_category = category
    if any(kw in desc_lower for kw in ['instagram', 'facebook', 'harass', 'stalk', 'threaten', 'abuse', 'morphic']):
        suggested_category = "Cyber Harassment"
    elif any(kw in desc_lower for kw in ['phishing', 'bank', 'link', 'otp', 'upi', 'scam', 'transaction', 'hacked']):
        suggested_category = "Financial Cyber Fraud"
    elif any(kw in desc_lower for kw in ['dark web', 'malware', 'ransomware', 'trojan', 'spyware']):
        suggested_category = "Malware/Ransomware Attack"

    # 4. Missing Information & Recommended Evidence
    missing_info = []
    recommended_evidence = []
    
    if "Cyber Harassment" in suggested_category:
        recommended_evidence.extend(["Profile URL of suspect", "Screenshots of chats", "Original email logs"])
        if "instagram" not in desc_lower and "facebook" not in desc_lower and "email" not in desc_lower:
            missing_info.append("Platform details (e.g., Instagram, Facebook, Gmail, etc.)")
            
    elif "Financial Cyber Fraud" in suggested_category:
        recommended_evidence.extend(["Transaction receipt / SMS screenshot", "Bank Account statement", "Payment Gateway link"])
        if "txn" not in desc_lower and "transaction" not in desc_lower:
            missing_info.append("Transaction ID / UPI Reference Number")
        if financial_loss == 0.0:
            missing_info.append("Exact monetary loss amount")
            
    else:
        recommended_evidence.extend(["Log files", "Screenshots of error/incident message"])
        
    if not incident_date_mentioned(description):
        missing_info.append("Incident timeline/date of occurrence")
        
    # 5. Extract Summary
    summary = f"A complaint regarding {suggested_category} occurring at this location."
    sentences = [s.strip() for s in re.split(r'[.!?]', description) if s.strip()]
    if sentences:
        # Use first two sentences as summary
        summary = ". ".join(sentences[:2]) + "."
        if len(summary) > 200:
            summary = summary[:197] + "..."
            
    return {
        'suggested_category': suggested_category,
        'suggested_priority': priority,
        'priority_reason': " / ".join(priority_reasons),
        'missing_info': ", ".join(missing_info) if missing_info else "None",
        'recommended_evidence': ", ".join(recommended_evidence) if recommended_evidence else "Relevant logs and screenshots",
        'extracted_indicators': ", ".join(indicators) if indicators else "",
        'summary': summary
    }

def incident_date_mentioned(description):
    """Check if numbers resembling dates are present in the text."""
    # Matches formats like dd/mm/yyyy, dd-mm-yyyy, yyyy-mm-dd, 18th Aug, etc.
    patterns = [
        r'\d{2}[-/]\d{2}[-/]\d{4}',
        r'\d{4}[-/]\d{2}[-/]\d{2}',
        r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d+',
        r'\d+(st|nd|rd|th)\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)'
    ]
    desc_lower = description.lower()
    return any(re.search(p, desc_lower) for p in patterns)
