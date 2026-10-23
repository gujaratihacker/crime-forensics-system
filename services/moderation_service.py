import re

# Simple list of sensitive or toxic terms to moderate
TOXIC_KEYWORDS = [
    'kill', 'murder', 'shoot', 'bomb', 'beat up', 'destroy',
    'idiot', 'scumbag', 'retard', 'bastard', 'fraudster', 'crook'
]

def moderate_comment(text):
    """
    Evaluates comments for safety and privacy compliance.
    Flags comments containing threat words, slurs, phone numbers,
    email addresses, or physical addresses, redirecting them to moderation.
    """
    text_lower = text.lower()
    reasons = []
    
    # 1. Check for physical threat or abuse keywords
    for keyword in TOXIC_KEYWORDS:
        if keyword in text_lower:
            reasons.append(f"Abusive/Threat keyword detected: '{keyword}'")
            
    # 2. Check for Phone Numbers (Privacy protection: doxxing prevention)
    phone_matches = re.findall(r"\b\d{10,12}\b", text)
    if phone_matches:
        reasons.append("Contains contact phone number (potential privacy exposure/doxxing)")
        
    # 3. Check for Email Addresses
    email_matches = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    if email_matches:
        reasons.append("Contains email address (potential privacy exposure)")
        
    # 4. Check for direct accusations or addresses (e.g., "lives at", "house number", "address is")
    address_keywords = ['lives at', 'address is', 'resides in', 'house number', 'my phone is']
    if any(ak in text_lower for ak in address_keywords):
        reasons.append("Contains physical address or contact reference indicators")
        
    if reasons:
        return {
            'is_flagged': True,
            'moderation_status': 'pending',
            'reason': " | ".join(reasons)
        }
        
    return {
        'is_flagged': False,
        'moderation_status': 'approved',
        'reason': 'Passed safety filters.'
    }
