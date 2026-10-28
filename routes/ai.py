from flask import Blueprint, render_template, request, jsonify, session
from utils.auth import login_required, roles_allowed, get_db_connection
from services.ai_analysis import (
    analyze_scam_or_threat,
    live_analyze_draft,
    polish_complaint_statement,
    generate_investigator_copilot,
    get_ai_chat_response
)

ai_bp = Blueprint('ai', __name__, url_prefix='/ai')

@ai_bp.route('/scam-detector', methods=['GET'])
def scam_detector():
    """Interactive CyberShield AI Scam & Phishing Diagnostic Center."""
    return render_template('ai/scam_detector.html')

@ai_bp.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint to scan suspicious messages, emails, or links."""
    data = request.get_json(silent=True) or request.form
    text_content = data.get('text', '')
    url_content = data.get('url', '')
    content_type = data.get('type', 'text')
    
    result = analyze_scam_or_threat(content_type, text_content, url_content)
    return jsonify({'status': 'success', 'data': result})

@ai_bp.route('/api/live-analyze', methods=['POST'])
def api_live_analyze():
    """Real-time reactive endpoint for report complaint forms."""
    data = request.get_json(silent=True) or request.form
    description = data.get('description', '')
    category = data.get('category', '')
    
    financial_loss_str = data.get('financial_loss', 0)
    try:
        financial_loss = float(financial_loss_str) if financial_loss_str else 0.0
    except (ValueError, TypeError):
        financial_loss = 0.0
        
    analysis = live_analyze_draft(description, category, financial_loss)
    return jsonify({'status': 'success', 'data': analysis})

@ai_bp.route('/api/polish', methods=['POST'])
def api_polish():
    """AI Complaint narrative structuring & enhancement."""
    data = request.get_json(silent=True) or request.form
    description = data.get('description', '')
    category = data.get('category', 'Cyber Crime')
    location = data.get('location', 'Online')
    incident_date = data.get('incident_date', '')
    suspect_info = data.get('suspect_info', '')
    
    try:
        financial_loss = float(data.get('financial_loss', 0))
    except (ValueError, TypeError):
        financial_loss = 0.0

    polished = polish_complaint_statement(
        description=description,
        category=category,
        location=location,
        incident_date=incident_date,
        financial_loss=financial_loss,
        suspect_info=suspect_info
    )
    return jsonify({'status': 'success', 'polished': polished})

@ai_bp.route('/api/chat', methods=['POST'])
def api_chat():
    """Interactive AI Counselor assistant endpoint."""
    data = request.get_json(silent=True) or request.form
    message = data.get('message', '')
    lang = session.get('lang', data.get('lang', 'en'))
    
    response_text = get_ai_chat_response(message, current_lang=lang)
    return jsonify({'status': 'success', 'response': response_text})

@ai_bp.route('/api/copilot/<case_id>', methods=['GET'])
@login_required
@roles_allowed('investigator', 'admin')
def api_copilot(case_id):
    """Investigator Case Copilot generation."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT ca.*, c.description, c.category, c.victim_info, c.suspect_info, c.financial_loss, c.location
                FROM cases ca
                JOIN complaints c ON ca.complaint_id = c.id
                WHERE ca.id = %s
            """, (case_id,))
            case_data = cursor.fetchone()
            if not case_data:
                return jsonify({'status': 'error', 'message': 'Case not found'}), 404
                
            copilot_data = generate_investigator_copilot(case_data)
            return jsonify({'status': 'success', 'copilot': copilot_data})
    finally:
        conn.close()

