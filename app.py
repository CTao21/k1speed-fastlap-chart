import os
import re
import imaplib
import csv
from datetime import datetime
from io import StringIO
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    jsonify, send_file, Response
)
from flask_sqlalchemy import SQLAlchemy
from email import message_from_bytes
from werkzeug.utils import secure_filename



app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////data/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    profile_pic = db.Column(db.String(200))
    leaderboard_consent = db.Column(db.Boolean, default=False)
    tracks = db.relationship('Track', backref='user', lazy=True)

class Track(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    raw_name = db.Column(db.String(80), nullable=False)  # Original from email
    display_name = db.Column(db.String(80), nullable=False)  # Formatted name
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sessions = db.relationship('Session', backref='track', lazy=True)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False)
    total_laps = db.Column(db.Integer)
    best_lap = db.Column(db.Float)
    avg_lap = db.Column(db.Float)
    fastest_lap_num = db.Column(db.Integer)
    lap_data = db.Column(db.Text)
    track_id = db.Column(db.Integer, db.ForeignKey('track.id'), nullable=False)

# Email Processing Core (From Old App)
def parse_email(msg, k1_name):
    """Working email parser from old version"""
    try:
        # Extract HTML body
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    body = part.get_payload(decode=True).decode("utf-8", "ignore")
                    break
        else:
            body = msg.get_payload(decode=True).decode("utf-8", "ignore")
        
        if not body:
            return None

        # Clean text
        txt = re.sub(r"<[^>]+>", " ", body)
        txt = re.sub(r"\s+", " ", txt).strip()

        # Extract laps
        laps = [float(m) for m in re.findall(r"\(\d+\)\s([\d.]+)", txt)]
        if len(laps) < 5 or min(laps) > 100:
            return None

        # Extract header
        header_match = re.search(
            r"LAPTIMES\s*-\s*([A-Za-z0-9\s]+?)\s+(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s[AP]M)",
            txt
        )
        if not header_match:
            return None

        loc_raw, date_str, time_str = header_match.groups()
        
        # Format location
        location = re.sub(r"\bT(\d)\b", r"Track \1", loc_raw.strip().title())
        
        # Parse date
        date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %I:%M %p")

        # Find best lap
        best_match = re.search(
            rf"{re.escape(k1_name)}\s+([\d.]+)\s+\d+\s+\d+\s+([\d.]+)",
            txt,
            re.IGNORECASE
        )
        if not best_match:
            return None

        return {
            "raw_location": loc_raw.strip(),
            "display_location": location,
            "date": date,
            "laps": laps,
            "best_lap": float(best_match.group(1)),
            "avg_lap": float(best_match.group(2)),
            "fastest_lap_num": laps.index(float(best_match.group(1))) + 1
        }
    except Exception as e:
        print(f"Parse error: {str(e)}")
        return None

# Routes (Your Current UI Flow)
@app.route('/')
def home():
    return redirect(url_for('imap_login'))

@app.route('/imap_login', methods=['GET', 'POST'])
def imap_login():
    if request.method == 'POST':
        try:
            session.clear()
            session['k1_name'] = request.form['k1_name']
            email_user = request.form['email_user']
            email_domain = request.form['email_domain']
            full_email = f"{email_user}@{email_domain}"
            
            imap_server = request.form['imap_server']
            imap_port = int(request.form['imap_port'])
            password = request.form['password']
            
            with imaplib.IMAP4_SSL(imap_server, imap_port) as mail:
                mail.login(full_email, password)
                mail.select('inbox')
            
            session['email'] = full_email
            session['imap_server'] = imap_server
            session['imap_port'] = imap_port
            session['password'] = password
            
            user = User.query.filter_by(email=full_email).first()
            return redirect(url_for('profile_found')) if user else redirect(url_for('profile_setup'))
            
        except Exception as e:
            flash(f"Login failed: {str(e)}", 'error')
    return render_template('imap_login.html')

from werkzeug.utils import secure_filename  # make sure this is at the top

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/profile_setup', methods=['GET', 'POST'])
def profile_setup():
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash("User not found. Please log in again.", "error")
        return redirect(url_for('imap_login'))

    if request.method == 'POST':
        try:
            # Update fields
            user.username = request.form['username']
            user.leaderboard_consent = 'consent' in request.form

            # Handle file upload
            if 'profile_pic_file' in request.files:
                file = request.files['profile_pic_file']
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                    upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(upload_path)
                    user.profile_pic = f"/static/uploads/{filename}"

            db.session.commit()
            return redirect(url_for('results'))

        except Exception as e:
            flash(f"Error updating profile: {str(e)}", 'error')

    return render_template('profile_setup.html')  # Form will be blank unless you prefillx





@app.route('/profile_found', methods=['GET', 'POST'])
def profile_found():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('imap_login'))
    
    if request.method == 'POST':
        return redirect(url_for('import_loading'))
    
    return render_template('profile_found.html',
                         username=user.username,
                         profile_pic=user.profile_pic,
                         consent=user.leaderboard_consent)

@app.route('/import_loading')
def import_loading():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    return render_template('import_loading.html')

@app.route('/import_results')
def import_results():
    if 'email' not in session:
        return jsonify({'status': 'error', 'message': 'Not logged in'})
    
    try:
        mail = imaplib.IMAP4_SSL(session['imap_server'], session['imap_port'])
        mail.login(session['email'], session['password'])
        mail.select('inbox')
        
        # Old app's working email search
        status, messages = mail.search(
            None,
            '(OR FROM "member@from.k1speed.com" FROM "noreply@from.k1speed.com") SUBJECT "Your Race Results"'
        )
        if status != 'OK':
            return jsonify({'status': 'error', 'message': 'Email search failed'})
        
        email_ids = messages[0].split()
        user = User.query.filter_by(email=session['email']).first()
        imported = 0

        for email_id in email_ids:
            try:
                status, msg_data = mail.fetch(email_id, '(RFC822)')
                msg = message_from_bytes(msg_data[0][1])
                race_data = parse_email(msg, session['k1_name'])
                
                if not race_data:
                    continue

                # Track handling
                track = Track.query.filter_by(
                    raw_name=race_data['raw_location'],
                    user_id=user.id
                ).first()
                
                if not track:
                    track = Track(
                        raw_name=race_data['raw_location'],
                        display_name=race_data['display_location'],
                        user_id=user.id
                    )
                    db.session.add(track)
                    db.session.commit()

                # Check for existing session
                existing = Session.query.filter_by(
                    track_id=track.id,
                    date=race_data['date']
                ).first()
                
                if not existing:
                    new_session = Session(
                        date=race_data['date'],
                        total_laps=len(race_data['laps']),
                        best_lap=race_data['best_lap'],
                        avg_lap=race_data['avg_lap'],
                        fastest_lap_num=race_data['fastest_lap_num'],
                        lap_data=str(race_data['laps']),
                        track_id=track.id
                    )
                    db.session.add(new_session)
                    imported += 1

            except Exception as e:
                print(f"Error processing email: {str(e)}")
                continue

        db.session.commit()
        mail.close()
        return jsonify({'status': 'success', 'imported': imported})
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/results')
def results():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('imap_login'))
    
    tracks_data = {}
    for track in user.tracks:
        sessions = track.sessions
        if sessions:
            best_session = min(sessions, key=lambda x: x.best_lap)
            first_session = min(sessions, key=lambda x: x.date)
            tracks_data[track.display_name] = {
                'raw_name': track.raw_name,
                'sessions': len(sessions),
                'first_date': first_session.date.strftime('%Y-%m-%d'),
                'best_lap': f"{best_session.best_lap:.3f}",
                'best_date': best_session.date.strftime('%Y-%m-%d')
            }
    
    return render_template('results.html',
                         username=user.username,
                         profile_pic=user.profile_pic,
                         tracks=tracks_data)

@app.route('/track/<track_name>')
def track_detail(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    
    user = User.query.filter_by(email=session['email']).first()
    track = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()
    
    sessions = []
    dates = []
    best_laps = []
    
    for s in track.sessions:
        laps = eval(s.lap_data) if s.lap_data else []
        sessions.append({
            'date': s.date.strftime('%Y-%m-%d %H:%M'),
            'total_laps': s.total_laps,
            'best_lap': f"{s.best_lap:.3f}",
            'avg_lap': f"{s.avg_lap:.3f}",
            'fastest_lap_num': s.fastest_lap_num,
            'laps': laps
        })
        dates.append(s.date.strftime('%Y-%m-%d'))
        best_laps.append(float(s.best_lap))
    
    # Compute improvement sessions only
    improvement_dates = []
    improvement_laps = []
    best_so_far = float('inf')

    for s in sorted(track.sessions, key=lambda x: x.date):
        if s.best_lap < best_so_far:
            best_so_far = s.best_lap
            improvement_dates.append(s.date.strftime('%Y-%m-%d %H:%M'))
            improvement_laps.append(float(s.best_lap))

    # Prepare chart data
    chart_data = {
        'dates': [s.date.strftime('%Y-%m-%d %H:%M') for s in track.sessions],
        'best_laps': [float(s.best_lap) for s in track.sessions],
        'improvement_dates': improvement_dates,
        'improvement_laps': improvement_laps
    }

    return render_template('track.html',
                           track_name=track.display_name,
                           sessions=sessions,
                           chart_data=chart_data,
                           username=user.username,
                           profile_pic=user.profile_pic)



@app.route('/download/<track_name>.csv')
def download(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    
    user = User.query.filter_by(email=session['email']).first()
    track = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Header
    headers = ['Date', 'Total Laps', 'Best Lap', 'Avg Lap', 'Fastest Lap #'] + [f'Lap {i}' for i in range(1, 17)]
    writer.writerow(headers)
    
    for s in track.sessions:
        laps = eval(s.lap_data) if s.lap_data else []
        row = [
            s.date.strftime('%Y-%m-%d %H:%M'),
            s.total_laps,
            s.best_lap,
            s.avg_lap,
            s.fastest_lap_num
        ] + laps[:16]
        writer.writerow(row)
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{track.display_name}.csv"'}
    )

@app.route('/leaderboard')
def leaderboard():
    tracks = [t[0] for t in db.session.query(Track.display_name).distinct().all()]
    return render_template('leaderboard.html', tracks=tracks)

@app.route('/leaderboard/<track_name>')
def track_leaderboard(track_name):
    # Find all tracks that match this display name
    matching_tracks = Track.query.filter_by(display_name=track_name).all()
    
    best_laps = []
    most_sessions = {}

    for track in matching_tracks:
        user = User.query.get(track.user_id)
        if not user or not user.leaderboard_consent:
            continue

        # Count sessions
        user_sessions = track.sessions
        if not user_sessions:
            continue

        # Update session count
        if user.id not in most_sessions:
            most_sessions[user.id] = {
                'username': user.username,
                'profile_pic': user.profile_pic,
                'session_count': 0,
                'first_date': min(s.date for s in user_sessions)
            }

        most_sessions[user.id]['session_count'] += len(user_sessions)

        # Find best lap session
        best_session = min(user_sessions, key=lambda s: s.best_lap)
        best_laps.append({
            'username': user.username,
            'profile_pic': user.profile_pic,
            'best_lap': best_session.best_lap,
            'best_date': best_session.date.strftime('%Y-%m-%d')
        })

    # Convert to sorted lists
    most_sessions_list = sorted(
        most_sessions.values(),
        key=lambda x: x['session_count'],
        reverse=True
    )

    best_laps_list = sorted(
        best_laps,
        key=lambda x: x['best_lap']
    )

    return render_template('track_leaderboard.html',
                           track_name=track_name,
                           most_sessions=most_sessions_list,
                           best_laps=best_laps_list)


# Render doesn’t use __main__, so we need to call create_all *every time*

with app.app_context():
    db.create_all()
