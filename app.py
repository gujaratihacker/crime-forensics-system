import os
from flask import Flask, redirect, url_for, session, render_template, request
from config import Config
from routes.auth import auth_bp
from routes.citizen import citizen_bp
from routes.admin import admin_bp
from routes.investigator import investigator_bp
from routes.complaints import complaints_bp
from routes.evidence import evidence_bp
from routes.live_incidents import live_bp
from routes.comments import comments_bp
from routes.missing_persons import missing_persons_bp
from routes.awareness import awareness_bp
from routes.social_media_crimes import social_media_crimes_bp
from utils.security import generate_csrf_token

app = Flask(__name__)
app.config.from_object(Config)

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(citizen_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(investigator_bp)
app.register_blueprint(complaints_bp)
app.register_blueprint(evidence_bp)
app.register_blueprint(live_bp)
app.register_blueprint(comments_bp)
app.register_blueprint(missing_persons_bp)
app.register_blueprint(awareness_bp)
app.register_blueprint(social_media_crimes_bp)

# Context processor to inject CSRF token and translation helpers globally
@app.context_processor
def inject_global_utilities():
    lang = session.get('lang', 'en')
    def translate(text_en, text_hi=None, text_gu=None):
        if lang == 'hi' and text_hi:
            return text_hi
        elif lang == 'gu' and text_gu:
            return text_gu
        return text_en
    return dict(csrf_token=generate_csrf_token(), translate=translate, current_lang=lang)

@app.route('/set-lang/<lang>')
def set_language(lang):
    if lang in ['en', 'hi', 'gu']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():

    if 'user_id' in session:
        role = session.get('role')
        if role == 'admin':
            return redirect(url_for('admin.dashboard'))
        elif role == 'investigator':
            return redirect(url_for('investigator.dashboard'))
        else:
            return redirect(url_for('citizen.dashboard'))
    return render_template('index.html')

# Custom Error Handlers
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

if __name__ == '__main__':
    # Verify folders exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    if not os.path.exists(app.config['LIVE_SNAPSHOTS_FOLDER']):
        os.makedirs(app.config['LIVE_SNAPSHOTS_FOLDER'])
    if not os.path.exists(app.config['MISSING_PERSONS_UPLOAD_FOLDER']):
        os.makedirs(app.config['MISSING_PERSONS_UPLOAD_FOLDER'])
        
    # Write fallback fallback image
    fallback_dir = os.path.join(app.root_path, 'static', 'images')
    if not os.path.exists(fallback_dir):
        os.makedirs(fallback_dir)
    fallback_path = os.path.join(fallback_dir, 'live_fallback.jpg')
    if not os.path.exists(fallback_path):
        with open(fallback_path, 'wb') as f:
            # Write 1x1 black pixel or empty binary placeholder
            f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\x27" #\x1c\x1c(7),01444\x1f\x27    =d\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x80\xff\xd9')

    app.run(debug=True, host='0.0.0.0', port=5000)
