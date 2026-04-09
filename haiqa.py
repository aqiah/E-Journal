from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt 
from flask_wtf.csrf import CSRFProtect 
from forms import RegistrationForm, LoginForm, JournalForm 
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from flask_talisman import Talisman 
from flask_limiter import Limiter 
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from functools import wraps

# --- Task 4: Load Secrets ---
load_dotenv() 

app = Flask(__name__)

# --- Task 1: Security Headers ---
Talisman(app, content_security_policy=None, force_https=False) 

# --- Task 2: Rate Limiting ---
limiter = Limiter(
    get_remote_address, 
    app=app, 
    default_limits=["200 per day"],
    storage_uri="memory://" 
)

# --- Configuration ---
app.config.update(
    SECRET_KEY=os.getenv('SECRET_KEY'),
    SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL'), 
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,   
    SESSION_COOKIE_SECURE=False,    
    SESSION_COOKIE_SAMESITE='Lax',
    UPLOAD_FOLDER='uploads'
)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)      
csrf = CSRFProtect(app)   

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    # Task 5: The "Admin Badge" exists but isn't checked in the "Before" phase
    is_admin = db.Column(db.Boolean, default=False)

class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

# --- Task 5: Admin Required Decorator (Defined but NOT used yet) ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_admin:
            abort(403) 
        return f(*args, **kwargs)
    return decorated_function

# --- ROUTES ---

@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = db.session.get(User, session['user_id'])
    entries = DiaryEntry.query.filter_by(user_id=user.id).order_by(DiaryEntry.date_posted.desc()).all()
    form = JournalForm()
    return render_template('index.html', user=user, entries=entries, form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful.', 'danger')
    return render_template('login.html', form=form)

# --- TASK 5: VULNERABLE ADMIN ROUTE (BEFORE MITIGATION) ---
# --- TASK 5: SECURE ADMIN ROUTE (AFTER MITIGATION) ---
@app.route('/admin')
@admin_required # This is the "Bouncer" that will now block you
def admin():
    # Fetch all users from the DB so the Admin can manage them
    all_users = User.query.all()
    
    # Building a simple dashboard UI
    user_list_html = "<ul>"
    for user in all_users:
        role_label = "[ADMIN]" if user.is_admin else "[USER]"
        user_list_html += f"<li>{user.username} {role_label} - <button disabled>Delete</button></li>"
    user_list_html += "</ul>"

    return f"""
    <h1>Secure Admin Dashboard</h1>
    <p>Logged in as: Admin</p>
    <hr>
    <h3>Manage Users:</h3>
    {user_list_html}
    <br>
    <a href='/'>Back to Journal</a>
    """

@app.route('/write', methods=['POST'])
def write():
    form = JournalForm()
    if 'user_id' in session and form.validate_on_submit():
        if 'entry_image' in request.files:
            file = request.files['entry_image']
            if file and file.filename != '':
                if not allowed_file(file.filename):
                    flash("Blocked! Invalid file type.", "danger")
                    return redirect(url_for('home'))
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        new_entry = DiaryEntry(
            user_id=session['user_id'],
            title=form.title.data,
            content=form.content.data
        )
        db.session.add(new_entry)
        db.session.commit()
        flash("Entry saved!", "success")
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# --- Task 3: File Upload Helpers ---
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['GET', 'POST'])
@csrf.exempt 
def lab8_upload():
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return f"<h1>Success!</h1><p>Saved as: {filename}</p><a href='/upload'>Back</a>"
        return "<h1>Blocked!</h1>"
    return '<form method=post enctype=multipart/form-data><input type=file name=file><input type=submit></form>'

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)