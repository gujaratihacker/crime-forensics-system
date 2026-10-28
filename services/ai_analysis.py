import os
import re
import urllib.parse
from datetime import datetime

def incident_date_mentioned(description):
    """Check if numbers resembling dates are present in the text."""
    patterns = [
        r'\d{2}[-/]\d{2}[-/]\d{4}',
        r'\d{4}[-/]\d{2}[-/]\d{2}',
        r'(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d+',
        r'\d+(st|nd|rd|th)\s+(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)'
    ]
    desc_lower = description.lower()
    return any(re.search(p, desc_lower) for p in patterns)


def extract_entities(text):
    """
    Extract structured forensic indicators from text:
    emails, phone numbers, URLs, UPI IDs, social handles, and crypto wallets.
    """
    if not text:
        return []

    entities = []
    seen = set()

    # Emails
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    email_domains = {'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'rediffmail.com', 'protonmail.com', 'email.com', 'forensics.local'}
    for e in emails:
        key = f"email:{e.lower()}"
        if key not in seen:
            seen.add(key)
            entities.append({'type': 'email', 'value': e, 'display': f"📧 {e}", 'raw': f"email:{e}"})

    # Phone numbers (+91..., 10-12 digits)
    phones = re.findall(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}", text)
    for p in phones:
        clean_p = re.sub(r'[\s\-\(\)]', '', p)
        if len(clean_p) >= 10:
            key = f"phone:{clean_p}"
            if key not in seen:
                seen.add(key)
                entities.append({'type': 'phone', 'value': p.strip(), 'display': f"📞 {p.strip()}", 'raw': f"phone:{clean_p}"})

    # URLs
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", text)
    for u in urls:
        full_u = u if u.startswith('http') else f"https://{u}"
        key = f"url:{full_u.lower()}"
        if key not in seen:
            seen.add(key)
            entities.append({'type': 'url', 'value': full_u, 'display': f"🔗 {full_u}", 'raw': f"url:{full_u}"})

    # UPI IDs (username@bank, excluding standard email domains)
    upis_raw = re.findall(r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9_\-]{2,}", text)
    for upi in upis_raw:
        parts = upi.split('@')
        domain = parts[1].lower()
        if domain not in email_domains and not domain.endswith(('.com', '.org', '.net', '.edu', '.gov', '.io')):
            key = f"upi:{upi.lower()}"
            if key not in seen:
                seen.add(key)
                entities.append({'type': 'upi', 'value': upi, 'display': f"💳 UPI: {upi}", 'raw': f"upi:{upi}"})

    # Social Handles (@username)
    handles = re.findall(r"(?<!\w)@([a-zA-Z0-9_]{3,25})\b", text)
    for h in handles:
        key = f"handle:@{h.lower()}"
        if key not in seen:
            seen.add(key)
            entities.append({'type': 'handle', 'value': f"@{h}", 'display': f"👤 @{h}", 'raw': f"handle:@{h}"})

    # Crypto Wallet addresses (Bitcoin or Ethereum heuristic)
    eth_wallets = re.findall(r"\b0x[a-fA-F0-9]{40}\b", text)
    for w in eth_wallets:
        key = f"crypto:{w.lower()}"
        if key not in seen:
            seen.add(key)
            entities.append({'type': 'crypto', 'value': w, 'display': f"🪙 ETH: {w[:6]}...{w[-4:]}", 'raw': f"crypto:{w}"})

    btc_wallets = re.findall(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b", text)
    for w in btc_wallets:
        key = f"crypto:{w}"
        if key not in seen:
            seen.add(key)
            entities.append({'type': 'crypto', 'value': w, 'display': f"🪙 BTC: {w[:6]}...{w[-4:]}", 'raw': f"crypto:{w}"})

    return entities


def analyze_complaint(description, category, financial_loss=0.0):
    """
    Core AI analysis of a complaint description and details.
    Uses regex, NLP keyword scoring, and heuristic pattern matching.
    Preserves 100% backward-compatibility for database and existing tests.
    """
    desc_lower = (description or "").lower()
    
    # 1. Extract Suspect Indicators
    entities = extract_entities(description or "")
    indicators = [e['raw'] for e in entities]
    
    # 2. Priority & Threat Scoring
    priority = "LOW"
    priority_reasons = []
    urgency_score = 25
    
    # Critical threat indicators
    critical_keywords = ['kill', 'harm', 'suicide', 'stalk', 'threaten', 'extort', 'blackmail', 'death', 'leak photo', 'morph', 'kidnap', 'deepfake', 'private photo']
    critical_matches = [kw for kw in critical_keywords if kw in desc_lower]
    
    if critical_matches:
        priority = "CRITICAL"
        urgency_score = 95
        priority_reasons.append(f"Immediate safety threat: Keywords relating to physical safety, extortion, or blackmail detected ({', '.join(critical_matches[:3])}).")
    elif financial_loss >= 50000:
        priority = "HIGH"
        urgency_score = 80
        priority_reasons.append("High financial loss: Loss is equal to or greater than Rs. 50,000.")
    elif financial_loss > 0 or any(kw in desc_lower for kw in ['loss', 'bank', 'transfer', 'credit card', 'otp', 'scam', 'fraud', 'unauthorized', 'stolen']):
        priority = "MEDIUM"
        urgency_score = 55
        priority_reasons.append("Financial fraud: Cyber fraud indicators or financial loss reported.")
        
    if not priority_reasons:
        priority_reasons.append("Standard priority: No urgent safety threats or high financial values detected.")
        
    # 3. Category Detection
    suggested_category = category or "Other"
    if any(kw in desc_lower for kw in ['instagram', 'facebook', 'harass', 'stalk', 'threaten', 'abuse', 'morphic', 'nude', 'blackmail', 'bullying']):
        suggested_category = "Cyber Harassment"
    elif any(kw in desc_lower for kw in ['phishing', 'bank', 'link', 'otp', 'upi', 'scam', 'transaction', 'hacked', 'deducted', 'credited', 'card', 'kyc']):
        suggested_category = "Financial Cyber Fraud"
    elif any(kw in desc_lower for kw in ['impersonat', 'fake profile', 'identity', 'stole my picture', 'stole my photo', 'fake account']):
        suggested_category = "Identity Theft"
    elif any(kw in desc_lower for kw in ['dark web', 'malware', 'ransomware', 'trojan', 'spyware', 'encrypted files', 'virus']):
        suggested_category = "Malware/Ransomware Attack"
    elif any(kw in desc_lower for kw in ['defaced', 'hacked website', 'website compromised', 'ddos']):
        suggested_category = "Website Defacement"

    # 4. Missing Information & Recommended Evidence
    missing_info = []
    recommended_evidence = []
    
    if "Cyber Harassment" in suggested_category:
        recommended_evidence.extend(["Profile URL of suspect", "Screenshots of chats", "Original email/message headers"])
        if "instagram" not in desc_lower and "facebook" not in desc_lower and "email" not in desc_lower and "whatsapp" not in desc_lower:
            missing_info.append("Platform details (e.g., Instagram, WhatsApp, Facebook, etc.)")
    elif "Financial Cyber Fraud" in suggested_category:
        recommended_evidence.extend(["Transaction receipt / SMS screenshot", "Bank Account statement", "Payment Gateway link / UTR"])
        if "txn" not in desc_lower and "transaction" not in desc_lower and "utr" not in desc_lower:
            missing_info.append("Transaction ID / UPI Reference Number (UTR)")
        if financial_loss == 0.0:
            missing_info.append("Exact monetary loss amount")
    elif "Identity Theft" in suggested_category:
        recommended_evidence.extend(["Link to impersonating profile", "Comparison of authentic vs fake account", "Original identity proof"])
        missing_info.append("Impersonating URL / Account ID")
    else:
        recommended_evidence.extend(["Log files", "Screenshots of error/incident message"])
        
    if not incident_date_mentioned(description or ""):
        missing_info.append("Incident timeline/date of occurrence")
        
    # 5. Summary Generation
    summary = f"A complaint regarding {suggested_category} occurring at this location."
    sentences = [s.strip() for s in re.split(r'[.!?]', description or "") if s.strip()]
    if sentences:
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
        'summary': summary,
        'urgency_score': urgency_score,
        'entities': entities
    }


def live_analyze_draft(description, category="", financial_loss=0.0):
    """
    Real-time interactive analysis payload designed for the frontend AI Co-Pilot
    as the user types in complaint and report forms.
    """
    raw_analysis = analyze_complaint(description, category, financial_loss)
    desc_lower = (description or "").lower()
    
    # Check completeness
    checks = []
    checks.append({
        'title': 'Incident Description Depth',
        'passed': len(description.strip()) >= 50 if description else False,
        'tip': 'Detailed description (>50 chars) speeds up forensic evaluation.'
    })
    checks.append({
        'title': 'Suspect Touchpoint / Contact',
        'passed': bool(raw_analysis['entities']),
        'tip': 'Include at least one suspect contact (Phone, UPI, Email, or Profile link).'
    })
    checks.append({
        'title': 'Date & Time Mentioned',
        'passed': incident_date_mentioned(description or ""),
        'tip': 'Provide exact date or approximate timeframe of incident.'
    })
    if category == 'Financial Cyber Fraud' or financial_loss > 0 or any(w in desc_lower for w in ['bank', 'loss', 'upi', 'otp']):
        has_txn = any(w in desc_lower for w in ['utr', 'transaction', 'txn', 'ref', 'reference'])
        checks.append({
            'title': 'Transaction Reference / UTR',
            'passed': has_txn,
            'tip': 'UTR / Reference Number is critical for bank nodal account freezing.'
        })

    # Red flags identified
    red_flags = []
    if any(k in desc_lower for k in ['otp', 'cvv', 'pin', 'anydesk', 'teamviewer', 'rustdesk']):
        red_flags.append("Remote Access or Sensitive Credential Compromise detected (OTP/PIN/Remote App).")
    if any(k in desc_lower for k in ['kyc', 'electricity', 'sim block', 'pan card', 'deactivate']):
        red_flags.append("Utility / KYC Urgency Impersonation vector identified.")
    if any(k in desc_lower for k in ['morph', 'nude', 'video call', 'blackmail', 'extort']):
        red_flags.append("High-severity Cyber Blackmail / Sextortion threat vector.")
    if any(k in desc_lower for k in ['telegram', 'task', 'youtube like', 'crypto', 'daily profit']):
        red_flags.append("Prevalent Part-Time Task / Ponzi Fraud signature.")

    # Actionable safety advice
    safety_advice = []
    if "Financial Cyber Fraud" in raw_analysis['suggested_category'] or financial_loss > 0:
        safety_advice.append("Call National Cyber Helpline 1930 immediately to trigger Golden Hour bank account freeze.")
        safety_advice.append("Take screenshots of bank SMS, UPI debit confirmation, and chat logs before blocking.")
    elif "Cyber Harassment" in raw_analysis['suggested_category']:
        safety_advice.append("Do NOT delete chat history or call recordings; export full WhatsApp/Instagram chat backups as evidence.")
        safety_advice.append("Block the suspect on social platforms, but preserve their handle, profile URL, and phone number.")
    else:
        safety_advice.append("Preserve original screenshots, system logs, and URLs without modification.")

    # Color badge mapping
    p_map = {
        'LOW': {'color': 'success', 'bg': '#10b981', 'label': 'Standard Priority'},
        'MEDIUM': {'color': 'warning', 'bg': '#f59e0b', 'label': 'Moderate Urgency'},
        'HIGH': {'color': 'danger', 'bg': '#ef4444', 'label': 'High Urgency'},
        'CRITICAL': {'color': 'dark', 'bg': '#7c3aed', 'label': 'CRITICAL THREAT'}
    }
    badge_info = p_map.get(raw_analysis['suggested_priority'], p_map['LOW'])

    return {
        'suggested_category': raw_analysis['suggested_category'],
        'suggested_priority': raw_analysis['suggested_priority'],
        'urgency_score': raw_analysis['urgency_score'],
        'priority_label': badge_info['label'],
        'priority_color': badge_info['color'],
        'priority_bg': badge_info['bg'],
        'priority_reason': raw_analysis['priority_reason'],
        'extracted_entities': raw_analysis['entities'],
        'missing_info': raw_analysis['missing_info'],
        'recommended_evidence': raw_analysis['recommended_evidence'],
        'summary': raw_analysis['summary'],
        'completeness_checks': checks,
        'red_flags': red_flags,
        'safety_advice': safety_advice
    }


def polish_complaint_statement(description, category="Cyber Crime", location="Online", incident_date="", financial_loss=0.0, suspect_info=""):
    """
    Transforms unstructured, conversational or emotionally written citizen reports
    into a structured, formal cyber incident statement ready for prosecution.
    """
    if not description or len(description.strip()) < 10:
        return description

    entities = extract_entities(f"{description} {suspect_info}")
    entity_str = ", ".join([e['display'] for e in entities]) if entities else (suspect_info or "Not known / Provided in attachments")
    
    today_str = datetime.now().strftime("%d-%b-%Y")
    inc_date_str = incident_date if incident_date else "Recently / Ongoing"
    loss_str = f"INR {financial_loss:,.2f}" if financial_loss and financial_loss > 0 else "Nil reported at time of drafting"

    # Clean description into sentences
    cleaned_desc = description.strip()

    structured = f"""======================================================
FORMAL CYBER INCIDENT REPORT & INVESTIGATIVE STATEMENT
======================================================

1. INCIDENT CLASSIFICATION:
   • Primary Category : {category}
   • Incident Timeline: {inc_date_str}
   • Jurisdiction/Locus: {location or 'Digital Network / Online'}
   • Recorded Date    : {today_str}

2. STATEMENT OF FACTS & MODUS OPERANDI:
{cleaned_desc}

3. SUSPECT IDENTIFIERS & DIGITAL FOOTPRINTS:
   • Accused Touchpoints: {entity_str}
   • Platform / Medium : {location}

4. IMPACT & DAMAGES ASSESSMENT:
   • Direct Monetary Loss  : {loss_str}
   • Personal / Cyber Safety Impact: Reported unauthorized breach / harassment.

5. PRAYER & INVESTIGATIVE ASSISTANCE REQUESTED:
   • Kindly initiate digital preservation of suspect accounts and IP connection logs.
   • Issue statutory preservation directives to concerned intermediaries/banks.
   • Secure hash verification of digital evidence submitted to prevent spoliation.

[Digitally compiled via Civic Desk Forensic AI Assistant]"""
    return structured


def analyze_scam_or_threat(content_type="text", text_content="", url_content=""):
    """
    Dedicated Multi-Vector Scam & Phishing Analyzer.
    Examines text, SMS, WhatsApp forwards, or URLs for deceptive patterns.
    """
    combined_text = f"{text_content or ''} {url_content or ''}".strip()
    text_lower = combined_text.lower()
    
    if not combined_text:
        return {
            'risk_score': 0,
            'verdict': 'NO CONTENT',
            'verdict_badge': 'secondary',
            'scam_type': 'None',
            'indicators': [],
            'tactics': [],
            'recommendations': []
        }

    score = 10
    detected_indicators = []
    tactics = []
    scam_type = "Potential Suspicious Communication"

    # 1. URL Analysis
    urls = re.findall(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", combined_text)
    if url_content and url_content not in urls:
        urls.append(url_content)

    for u in urls:
        parsed = urllib.parse.urlparse(u if u.startswith('http') else f"https://{u}")
        host = parsed.netloc.lower()
        
        # IP in URL
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host.split(':')[0]):
            score += 40
            detected_indicators.append(f"Deceptive Host: Direct IP address in link ({host}) instead of registered domain.")
            tactics.append("Network Obfuscation")

        # Suspicious TLDs
        suspicious_tlds = ('.xyz', '.top', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.live', '.loan', '.work', '.casa', '.monster')
        if host.endswith(suspicious_tlds):
            score += 35
            detected_indicators.append(f"High-Risk TLD: Domain uses extension often associated with disposable scams ({host}).")
            tactics.append("Disposable Infrastructure")

        # URL Shorteners hiding destination
        shorteners = ('bit.ly', 'tinyurl.com', 'is.gd', 'cutt.ly', 'rb.gy', 't.co', 'ow.ly')
        if any(s in host for s in shorteners):
            score += 25
            detected_indicators.append(f"URL Shortener ({host}) masks real destination server.")
            tactics.append("Destination Concealment")

        # Impersonated brands in domain
        popular_brands = ['sbi', 'hdfc', 'icici', 'paytm', 'phonepe', 'gpay', 'netflix', 'amazon', 'flipkart', 'telegram', 'whatsapp', 'jio', 'airtel']
        for b in popular_brands:
            if b in host and not (host.endswith(f".{b}.com") or host.endswith(f".{b}.in") or host == f"{b}.com" or host == f"{b}.in"):
                score += 45
                detected_indicators.append(f"Brand Impersonation / Typosquatting: '{b}' found inside unofficial domain '{host}'.")
                tactics.append("Brand Spoofing")
                scam_type = f"Phishing / Fake {b.upper()} Portal"

    # 2. Text Content Heuristics & Modus Operandi Matching
    
    # Banking / KYC / SIM Block
    if any(k in text_lower for k in ['kyc', 'pan card', 'deactivate', 'block your account', 'suspend your card', 'electricity bill', 'power disconnected']):
        score += 40
        detected_indicators.append("Urgent KYC/Utility suspension ultimatum designed to induce panic.")
        tactics.append("Fear & Panic Induction")
        scam_type = "Banking KYC / Utility Disconnection Phishing"

    # Part-time Job / YouTube / Telegram
    if any(k in text_lower for k in ['part time', 'work from home', 'daily income', 'earn 3000', 'earn 5000', 'like youtube video', 'subscribe and earn', 'telegram task']):
        score += 45
        detected_indicators.append("Prevalent 'Part-time Task/YouTube review' fraudulent Ponzi solicitation.")
        tactics.append("Financial Greed & False Employment")
        scam_type = "Part-Time Task & Investment Ponzi Scam"

    # Blackmail / Sextortion / Video Call
    if any(k in text_lower for k in ['leak your video', 'private photo', 'nude', 'call recording', 'pay or i will send to all friends', 'send money on upi or viral']):
        score += 55
        detected_indicators.append("Coercive Extortion & Non-consensual Media Leak threat.")
        tactics.append("Sextortion & Criminal Intimidation")
        scam_type = "Sextortion / Digital Blackmail Threat"

    # Digital Arrest / Fake Police / CBI
    if any(k in text_lower for k in ['digital arrest', 'customs', 'parcel seized', 'drugs found', 'mumbai police', 'cbi officer', 'narcotics', 'arrest warrant']):
        score += 50
        detected_indicators.append("High-profile 'Digital Arrest' impersonation of Law Enforcement / Customs.")
        tactics.append("State Authority Impersonation")
        scam_type = "Fake Law Enforcement / Digital Arrest Scam"

    # Lottery / Prize / Gift
    if any(k in text_lower for k in ['lottery', 'prize', 'lucky draw', 'jackpot', 'congratulations', 'won 25 lakh', 'won a prize', 'claim reward', 'winner', 'cash prize']):
        score += 40
        detected_indicators.append("Unsolicited Lottery / Prize Claim lure with advance fee requirement.")
        tactics.append("Advance Fee Fraud")
        scam_type = "Lottery & Lucky Draw Prize Fraud"

    # UPI Overpayment / QR Code reverse scam
    if any(k in text_lower for k in ['scan qr to receive', 'enter pin to receive money', 'overpaid you', 'send back refund']):
        score += 45
        detected_indicators.append("UPI PIN reversal scam: Scanning QR code or entering UPI PIN only DEDUCTS money, never credits.")
        tactics.append("Reverse UPI Fraud")
        scam_type = "UPI QR Code / False Refund Scam"

    # Remote Access Apps
    if any(k in text_lower for k in ['anydesk', 'teamviewer', 'rustdesk', 'quicksupport', 'screen share']):
        score += 40
        detected_indicators.append("Request to install remote desktop tool (AnyDesk/TeamViewer/RustDesk) to hijack device.")
        tactics.append("Remote Device Hijacking")

    # Pressure keywords
    if any(k in text_lower for k in ['immediately', 'within 2 hours', 'urgent', 'last warning', 'today only', 'expire today']):
        score += 20
        detected_indicators.append("High-pressure urgency timer to prevent victim from consulting family or bank.")
        tactics.append("Manufactured Time Pressure")

    # Entities extracted
    entities = extract_entities(combined_text)

    # Normalize score
    final_score = min(max(score, 15 if detected_indicators else 5), 99)

    # Verdict
    if final_score >= 75:
        verdict = "CRITICAL RISK / CONFIRMED SCAM"
        verdict_badge = "danger"
    elif final_score >= 50:
        verdict = "HIGH RISK SUSPICIOUS"
        verdict_badge = "warning"
    elif final_score >= 30:
        verdict = "MODERATE RISK"
        verdict_badge = "info"
    else:
        verdict = "LOW RISK / LIKELY BENIGN"
        verdict_badge = "success"
        scam_type = "No Known Threat Pattern"

    # Tailored recommendations
    recommendations = []
    if final_score >= 50:
        recommendations.append("DO NOT click any links, open APK downloads, or enter OTP/UPI PIN.")
        recommendations.append("Never entertain callers claiming to be Police/CBI on Skype or WhatsApp video calls ('Digital Arrest' is fake).")
        recommendations.append("If money has been deducted, immediately call the National Cyber Helpline at 1930.")
        recommendations.append("Block the sender and export the chat/SMS for evidence reporting.")
    else:
        recommendations.append("Verify sender identity through official verified websites or toll-free numbers.")
        recommendations.append("Remember: Banks, Government bodies, and UPI never request OTP or PIN for receiving funds.")

    return {
        'risk_score': final_score,
        'verdict': verdict,
        'verdict_badge': verdict_badge,
        'scam_type': scam_type,
        'indicators': detected_indicators if detected_indicators else ["No overt phishing keywords or deceptive domains detected in sample."],
        'tactics': list(set(tactics)) if tactics else ["Standard Communication"],
        'recommendations': recommendations,
        'extracted_entities': entities,
        'prefill_data': {
            'category': 'Financial Cyber Fraud' if any(t in scam_type for t in ['Banking', 'Task', 'UPI', 'Lottery']) else 'Cyber Harassment',
            'description': f"Report regarding suspicious message received:\n\n{combined_text}",
            'suspect_info': ", ".join([e['display'] for e in entities]) if entities else "Unknown contact"
        }
    }


def generate_investigator_copilot(case_dict):
    """
    Synthesizes case facts for investigators, proposing Modus Operandi (M.O.),
    applicable Indian IT Act & BNS/IPC legal provisions, and evidence gaps.
    """
    category = case_dict.get('category', '')
    desc = (case_dict.get('description', '') or "").lower()
    
    # 1. Modus Operandi (M.O.)
    mo_type = "General Cyber Incident"
    if any(w in desc for w in ['telegram', 'task', 'part time']):
        mo_type = "Task-Based Crypto/UPI Layered Ponzi Scheme"
    elif any(w in desc for w in ['kyc', 'pan', 'electricity', 'apk']):
        mo_type = "Smishing with Malicious APK Dropper & Vishing Intercept"
    elif any(w in desc for w in ['morph', 'nude', 'video call', 'extort']):
        mo_type = "Non-Consensual Video Capture & Organized Sextortion Racket"
    elif any(w in desc for w in ['digital arrest', 'customs', 'cbi']):
        mo_type = "State Authority Impersonation (Digital Arrest Syndicate)"
    elif any(w in desc for w in ['fake profile', 'impersonat', 'instagram']):
        mo_type = "Social Media Identity Hijacking & Defamation"
    elif any(w in desc for w in ['ransomware', 'encrypted', 'decrypt']):
        mo_type = "Targeted Ransomware Extortion via Exposed Services"

    # 2. Suggested Legal Sections (IT Act 2000 & Bharatiya Nyaya Sanhita 2023 / IPC)
    sections = [
        {'act': 'Information Technology Act, 2000', 'section': 'Section 66', 'desc': 'Computer related offences & hacking.'}
    ]
    if "Financial" in category or "Fraud" in category or any(w in desc for w in ['loss', 'bank', 'money', 'upi']):
        sections.append({'act': 'IT Act, 2000', 'section': 'Section 66D', 'desc': 'Punishment for cheating by personation by using computer resource.'})
        sections.append({'act': 'Bharatiya Nyaya Sanhita (BNS)', 'section': 'Section 318(4) / IPC 420', 'desc': 'Cheating and dishonestly inducing delivery of property.'})
        sections.append({'act': 'Bharatiya Nyaya Sanhita (BNS)', 'section': 'Section 319 / IPC 419', 'desc': 'Punishment for cheating by personation.'})
    if "Harassment" in category or any(w in desc for w in ['stalk', 'threaten', 'abuse', 'morph']):
        sections.append({'act': 'IT Act, 2000', 'section': 'Section 66E', 'desc': 'Punishment for violation of privacy.'})
        sections.append({'act': 'IT Act, 2000', 'section': 'Section 67 / 67A', 'desc': 'Publishing or transmitting obscene material in electronic form.'})
        sections.append({'act': 'Bharatiya Nyaya Sanhita (BNS)', 'section': 'Section 351 / IPC 506', 'desc': 'Punishment for criminal intimidation.'})
        sections.append({'act': 'Bharatiya Nyaya Sanhita (BNS)', 'section': 'Section 78 / IPC 354D', 'desc': 'Stalking via electronic communication.'})
    if "Identity" in category or any(w in desc for w in ['impersonat', 'fake profile']):
        sections.append({'act': 'IT Act, 2000', 'section': 'Section 66C', 'desc': 'Punishment for identity theft.'})

    # 3. Critical Evidence Checklist for Case Officer
    evidence_checklist = [
        {'item': 'Bank Nodal Freeze Letter', 'desc': 'Formal directive to freeze suspected mule accounts connected to transaction UTR.', 'critical': True},
        {'item': 'IPDR & CDR Analysis', 'desc': 'Requisition Internet Protocol Detail Records and Call Detail Records from Telecom Service Providers.', 'critical': True},
        {'item': 'Section 91 CrPC Preservation Notice', 'desc': 'Notice to Meta, Google, or Telegram to preserve account logs, registration IP, and 2FA phone.', 'critical': True},
        {'item': 'Cryptographic Hash Check', 'desc': 'Verify SHA-256 evidence integrity in digital vault before submitting chargesheet.', 'critical': False}
    ]

    return {
        'modus_operandi': mo_type,
        'legal_sections': sections,
        'evidence_checklist': evidence_checklist,
        'urgency_assessment': case_dict.get('priority', 'MEDIUM')
    }


def get_ai_chat_response(message, current_lang="en"):
    """
    Interactive Cyber Assistant (CyberShield AI Counselor).
    Provides instant, compassionate, and technically accurate safety guidance.
    """
    msg_lower = (message or "").lower()
    
    # Language specific greetings
    if current_lang == 'hi':
        greeting = "नमस्ते! मैं आपका साइबर सुरक्षा सहायक (CyberShield AI) हूँ।"
        helpline = "🚨 तुरंत आपातकालीन सहायता: राष्ट्रीय साइबर हेल्पलाइन 1930 पर कॉल करें या cybercrime.gov.in पर जाएँ।"
    elif current_lang == 'gu':
        greeting = "નમસ્તે! હું તમારો સાયબર સુરક્ષા સહાયક (CyberShield AI) છું."
        helpline = "🚨 તાત્કાલિક સહાય: રાષ્ટ્રીય સાયબર હેલ્પલાઇન 1930 પર કૉલ કરો અથવા cybercrime.gov.in ની મુલાકાત લો."
    else:
        greeting = "Hello! I am your CyberShield AI Safety Companion."
        helpline = "🚨 Emergency Assistance: Call the National Cyber Helpline 1930 immediately or visit cybercrime.gov.in."

    # Response matrix
    if any(k in msg_lower for k in ['money', 'lost', 'debit', 'fraud', 'upi', 'bank', 'stolen', 'rupee', 'paisa', 'paise', 'kaka']):
        if current_lang == 'hi':
            return f"""{greeting}\n\n{helpline}\n\n**तुरंत उठाए जाने वाले 3 कदम:**\n1. **1930 पर कॉल करें**: घटना के पहले 2 से 3 घंटों ('गोल्डन ऑवर') में कॉल करने से बैंक जालसाज के खाते में पैसे फ्रीज कर सकता है।\n2. **बैंक को सूचित करें**: अपने बैंक के कस्टमर केयर पर कॉल करके संबंधित यूपीआई/कार्ड को तुरंत ब्लॉक करवाएं।\n3. **सबूत सुरक्षित रखें**: ट्रांजेक्शन UTR नंबर, एसएमएस और बैंक स्टेटमेंट का स्क्रीनशॉट लें और हमारे पोर्टल पर शिकायत दर्ज करें।"""
        elif current_lang == 'gu':
            return f"""{greeting}\n\n{helpline}\n\n**તરત લેવાના પગલાં:**\n1. **1930 પર કૉલ કરો**: પહેલાં 2-3 કલાકમાં કૉલ કરવાથી બેંક છેતરપિંડી કરનારના ખાતામાં નાણાં બ્લોક કરી શકે છે.\n2. **બેંકને જાણ કરો**: તમારા કાર્ડ અથવા યુપીઆઈને તરત બ્લોક કરાવો.\n3. **પુરાવા સાચવો**: UTR નંબર અને SMS નો સ્ક્રીનશૉટ રાખી અહીં ફરિયાદ નોંધાવો."""
        else:
            return f"""{greeting}\n\n{helpline}\n\n**Immediate Golden-Hour Steps:**\n1. **Dial 1930 Immediately**: Reporting within the first 2-3 hours enables the Citizen Financial Cyber Fraud Reporting System to freeze the funds in the suspect mule account.\n2. **Freeze Account/Cards**: Call your bank's official emergency helpline to block the compromised card or UPI handle.\n3. **Preserve Evidence**: Save the 12-digit UTR reference number, bank SMS, and payment confirmations. Then click **Report Cyber Crime** above to log a digital evidence file."""

    if any(k in msg_lower for k in ['harass', 'stalk', 'threaten', 'blackmail', 'morph', 'nude', 'photo', 'private', 'instagram', 'whatsapp']):
        if current_lang == 'hi':
            return f"""{greeting}\n\n**साइबर उत्पीड़न / ब्लैकमेल से निपटने के निर्देश:**\n1. **पैसे बिल्कुल न दें**: पैसे देने पर ब्लैकमेलर बार-बार और अधिक पैसों की मांग करते हैं।\n2. **चैट डिलीट न करें**: सभी संदेशों, कॉल्स, और ब्लैकमेलर के प्रोफाइल लिंक/फोन नंबर के स्क्रीनशॉट लें।\n3. **अनाम रिपोर्ट करें**: यदि आप अपनी पहचान गोपनीय रखना चाहते हैं, तो हमारे पोर्टल पर **Anonymous Report** विकल्प चुनें।"""
        else:
            return f"""{greeting}\n\n**Cyber Harassment & Extortion Protocol:**\n1. **DO NOT PAY**: Paying never stops extortion; it only invites repeated higher demands.\n2. **Preserve Digital Evidence**: Do NOT delete WhatsApp or Instagram chats. Take timestamped screenshots showing the suspect's handle, phone number, and profile URL.\n3. **Report Anonymously**: You can submit a secure, masked complaint on our portal using the **Report Anonymously** toggle.\n4. **Platform Reporting**: Use Instagram/WhatsApp in-app reporting tools to flag the account for harassment."""

    if any(k in msg_lower for k in ['scam', 'fake', 'link', 'check', 'suspicious', 'url', 'sms', 'message', 'job', 'task']):
        return f"""{greeting}\n\n💡 **Use our Interactive AI Scam Detector:**\nWe have built a dedicated **CyberShield AI Scam & Phishing Detector** in this portal!\n\n👉 Go to **Services > AI Scam Detector** or paste the suspicious message/URL there. The AI will evaluate:\n• Deceptive patterns and brand spoofing\n• Scam probability score (0-100%)\n• Extracted suspect contact numbers and UPIs\n• Immediate safety actions & one-click complaint filing."""

    # General fallback
    if current_lang == 'hi':
        return f"""{greeting}\n\nमैं आपकी कैसे मदद कर सकता हूँ? आप मुझसे पूछ सकते हैं:\n• "मेरे खाते से पैसे कट गए हैं, क्या करूँ?"\n• "सोशल मीडिया पर कोई ब्लैकमेल कर रहा है"\n• "क्या यह एसएमएस या लिंक फर्जी है?"\n• "डिजिटल साक्ष्य कैसे सुरक्षित रखें?"\n\n{helpline}"""
    else:
        return f"""{greeting}\n\nI am here to guide and safeguard you against online threats. You can ask me:\n• *"I lost money in an unauthorized online transaction"*\n• *"Someone is blackmailing me with edited photos"*\n• *"How do I check if a message or link is a scam?"*\n• *"How does anonymous reporting work on Civic Desk?"*\n\n{helpline}"""
