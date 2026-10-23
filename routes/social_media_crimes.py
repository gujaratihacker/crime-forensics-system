import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, abort
from utils.auth import login_required, roles_allowed, get_db_connection
from utils.security import sanitize_string, validate_csrf_token
from utils.audit import log_audit
from services.ai_analysis import analyze_complaint
from services.evidence_service import preserve_evidence
from routes.complaints import generate_complaint_id
from datetime import datetime

social_media_crimes_bp = Blueprint('social_media_crimes', __name__, url_prefix='/social-media-crimes')

@social_media_crimes_bp.route('/report', methods=['GET', 'POST'])
@login_required
@roles_allowed('citizen')
def report_crime():
    if request.method == 'POST':
        # CSRF check
        token = request.form.get('csrf_token')
        if not validate_csrf_token(token):
            flash("Security check failed (CSRF token missing or invalid).", "danger")
            return redirect(url_for('social_media_crimes.report_crime'))
            
        platform = sanitize_string(request.form.get('platform'))
        crime_type = sanitize_string(request.form.get('crime_type'))
        profile_url = sanitize_string(request.form.get('profile_url'))
        incident_date = sanitize_string(request.form.get('incident_date'))
        incident_time = sanitize_string(request.form.get('incident_time'))
        description = sanitize_string(request.form.get('description'))
        reporting_mode = sanitize_string(request.form.get('reporting_mode', 'identified'))
        
        # Validations
        if not all([platform, crime_type, profile_url, incident_date, incident_time, description]):
            flash("Please fill in all required fields marked with an asterisk (*).", "danger")
            return redirect(url_for('social_media_crimes.report_crime'))
            
        complaint_id = generate_complaint_id()
        user_id = session.get('user_id')
        
        # Structure descriptions for default view compatibility
        compiled_desc = f"Platform: {platform}\nCrime Type: {crime_type}\nProfile URL: {profile_url}\n\nDescription:\n{description}"
        
        # AI analysis on description
        ai_res = analyze_complaint(compiled_desc, 'Social Media Crime')
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # 1. Insert into complaints table
                sql = """
                INSERT INTO complaints (
                    id, citizen_id, category, incident_date, incident_time, location, 
                    description, victim_info, suspect_info, contact_indicators, financial_loss, 
                    additional_info, reporting_mode, status, priority, priority_reason, 
                    ai_category, ai_priority, ai_missing_info, ai_recommended_evidence, ai_summary
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, 
                    %s, %s, %s, %s, 0.00, 
                    %s, %s, 'submitted', %s, %s, 
                    %s, %s, %s, %s, %s
                )
                """
                suspect_indicators = f"url:{profile_url}"
                additional_meta = f"Social Media Incident | Platform: {platform} | Sub-category: {crime_type}"
                
                cursor.execute(sql, (
                    complaint_id, user_id, 'Social Media Crime', incident_date, incident_time, f"{platform} Platform",
                    compiled_desc, 'Social Media Account/Profile Holder', f"Platform Handle/URL: {profile_url}",
                    suspect_indicators, additional_meta, reporting_mode, ai_res['suggested_priority'],
                    ai_res['priority_reason'], ai_res['suggested_category'], ai_res['suggested_priority'],
                    ai_res['missing_info'], ai_res['recommended_evidence'], ai_res['summary']
                ))
                
                # 2. Insert into social_media_complaints table
                cursor.execute("""
                    INSERT INTO social_media_complaints (complaint_id, platform, crime_type, profile_url)
                    VALUES (%s, %s, %s, %s)
                """, (complaint_id, platform, crime_type, profile_url))
                

                # Handle evidence upload if present
                if 'evidence_file' in request.files:
                    file = request.files['evidence_file']
                    if file and file.filename:
                        preserve_evidence(
                            file_obj=file,
                            uploader_id=user_id,
                            complaint_id=complaint_id,
                            source='citizen'
                        )
                        
                # Log audit
                log_audit(
                    user_id=user_id,
                    action="COMPLAINT_SUBMIT",
                    case_id=None,
                    description=f"Submitted new Social Media Crime report {complaint_id} ({crime_type} on {platform})."
                )
                
            flash(f"Social Media Crime report submitted successfully. Complaint Ref: {complaint_id}", "success")
            return redirect(url_for('citizen.dashboard'))
            
        except Exception as e:
            flash(f"Failed to submit report. Please check details. Error: {str(e)}", "danger")
            print(f"SOCIAL CRIME REPORT ERROR: {e}")
        finally:
            conn.close()
            
    return render_template('social_media_crimes/report.html')
