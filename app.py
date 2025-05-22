import os
import re
import imaplib
import csv
from datetime import datetime
from io import StringIO

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    jsonify, Response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# email parsing imports
from email.parser import BytesParser
from email.policy import default

# --- Flask + DB setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////data/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(80), nullable=False)
    email               = db.Column(db.String(120), unique=True, nullable=False)
    profile_pic         = db.Column(db.String(200))
    leaderboard_consent = db.Column(db.Boolean, default=False)
    tracks              = db.relationship('Track', backref='user', lazy=True)

class Track(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    raw_name     = db.Column(db.String(80),  nullable=False)
    display_name = db.Column(db.String(80),  nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sessions     = db.relationship('Session', backref='track', lazy=True)

class Session(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    date            = db.Column(db.DateTime, nullable=False)
    total_laps      = db.Column(db.Integer)
    best_lap        = db.Column(db.Float)
    avg_lap         = db.Column(db.Float)
    fastest_lap_num = db.Column(db.Integer)
    lap_data        = db.Column(db.Text)
    track_id        = db.Column(db.Integer, db.ForeignKey('track.id'), nullable=False)

# --- Helpers ---
def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def extract_email_body(msg):
    """Extract text/html or text/plain body safely."""
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get('Content-Disposition'))
            if 'attachment' in disp:
                continue
            ctype = part.get_content_type()
            if ctype in ('text/plain', 'text/html'):
                try:
                    return part.get_payload(decode=True).decode('utf-8', 'ignore')
                except:
                    pass
    else:
        try:
            return msg.get_payload(decode=True).decode('utf-8', 'ignore')
        except:
            pass
    return None

def parse_email(msg, k1_name):
    """Return race dict or None."""
    body = extract_email_body(msg)
    if not body:
        print("⚠️ Empty body")
        return None

    # normalize HTML and whitespace
    body = re.sub(r'<br\s*/?>', ' ', body, flags=re.IGNORECASE)
    body = re.sub(r'<[^>]+>', ' ', body)
    text = re.sub(r'\s+', ' ', body).strip()

    # header: LAPTIMES - LOCATION 03/21/24 07:45 PM
    m = re.search(
        r"LAPTIMES\s*-\s*([A-Za-z0-9\s]+?)\s+(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s[AP]M)",
        text, re.IGNORECASE
    )
    if not m:
        print("❌ No header")
        return None
    loc_raw, date_str, time_str = m.groups()

    # parse date & location
    date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %I:%M %p")
    display_loc = re.sub(r"\bT(\d)\b", r"Track \1", loc_raw.strip().title())

    # extract lap times
    laps = [float(x) for x in re.findall(r"\(\d+\)\s*([\d.]+)", text)]
    if len(laps) < 5 or min(laps) > 100:
        print("❌ Invalid lap data")
        return None

    # best & avg by racer name
    nm = re.search(
        rf"{re.escape(k1_name)}\s+([\d.]+)\s+\d+\s+\d+\s+([\d.]+)",
        text, re.IGNORECASE
    )
    if not nm:
        print("❌ No name match")
        return None
    best_lap = float(nm.group(1))
    avg_lap  = float(nm.group(2))
    fastest_idx = laps.index(best_lap) + 1

    return {
        'raw_location':      loc_raw.strip(),
        'display_location':  display_loc,
        'date':              date,
        'laps':              laps,
        'best_lap':          best_lap,
        'avg_lap':           avg_lap,
        'fastest_lap_num':   fastest_idx
    }

# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('imap_login'))

@app.route('/imap_login', methods=['GET','POST'])
def imap_login():
    if request.method=='POST':
        try:
            session.clear()
            session['k1_name']    = request.form['k1_name']
            usern = request.form['email_user']
            dom   = request.form['email_domain']
            full_email = f"{usern}@{dom}"
            session['email']      = full_email
            session['imap_server']= request.form['imap_server']
            session['imap_port']  = int(request.form['imap_port'])
            session['password']   = request.form['password']

            # validate IMAP creds
            with imaplib.IMAP4_SSL(session['imap_server'], session['imap_port']) as M:
                M.login(full_email, session['password'])
                M.select('INBOX')

            # new vs returning
            if User.query.filter_by(email=full_email).first():
                return redirect(url_for('profile_found'))
            else:
                return redirect(url_for('profile_setup'))

        except Exception as e:
            flash(f"Login failed: {e}", 'error')

    return render_template('imap_login.html')

import os
import re
import imaplib
import csv
from datetime import datetime
from io import StringIO

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    jsonify, Response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# email parsing imports
from email.parser import BytesParser
from email.policy import default

# --- Flask + DB setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////data/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(80), nullable=False)
    email               = db.Column(db.String(120), unique=True, nullable=False)
    profile_pic         = db.Column(db.String(200))
    leaderboard_consent = db.Column(db.Boolean, default=False)
    tracks              = db.relationship('Track', backref='user', lazy=True)

class Track(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    raw_name     = db.Column(db.String(80),  nullable=False)
    display_name = db.Column(db.String(80),  nullable=False)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sessions     = db.relationship('Session', backref='track', lazy=True)

class Session(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    date            = db.Column(db.DateTime, nullable=False)
    total_laps      = db.Column(db.Integer)
    best_lap        = db.Column(db.Float)
    avg_lap         = db.Column(db.Float)
    fastest_lap_num = db.Column(db.Integer)
    lap_data        = db.Column(db.Text)
    track_id        = db.Column(db.Integer, db.ForeignKey('track.id'), nullable=False)

# --- Helpers ---
def allowed_file(filename):
    return (
        '.' in filename and
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    )

def extract_email_body(msg):
    """Extract text/html or text/plain body safely."""
    if msg.is_multipart():
        for part in msg.walk():
            disp = str(part.get('Content-Disposition'))
            if 'attachment' in disp:
                continue
            ctype = part.get_content_type()
            if ctype in ('text/plain', 'text/html'):
                try:
                    return part.get_payload(decode=True).decode('utf-8', 'ignore')
                except:
                    pass
    else:
        try:
            return msg.get_payload(decode=True).decode('utf-8', 'ignore')
        except:
            pass
    return None

def parse_email(msg, k1_name):
    """Return race dict or None."""
    body = extract_email_body(msg)
    if not body:
        print("⚠️ Empty body")
        return None

    # normalize HTML and whitespace
    body = re.sub(r'<br\s*/?>', ' ', body, flags=re.IGNORECASE)
    body = re.sub(r'<[^>]+>', ' ', body)
    text = re.sub(r'\s+', ' ', body).strip()

    # header: LAPTIMES - LOCATION 03/21/24 07:45 PM
    m = re.search(
        r"LAPTIMES\s*-\s*([A-Za-z0-9\s]+?)\s+(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s[AP]M)",
        text, re.IGNORECASE
    )
    if not m:
        print("❌ No header")
        return None
    loc_raw, date_str, time_str = m.groups()

    # parse date & location
    date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %I:%M %p")
    display_loc = re.sub(r"\bT(\d)\b", r"Track \1", loc_raw.strip().title())

    # extract lap times
    laps = [float(x) for x in re.findall(r"\(\d+\)\s*([\d.]+)", text)]
    if len(laps) < 5 or min(laps) > 100:
        print("❌ Invalid lap data")
        return None

    # best & avg by racer name
    nm = re.search(
        rf"{re.escape(k1_name)}\s+([\d.]+)\s+\d+\s+\d+\s+([\d.]+)",
        text, re.IGNORECASE
    )
    if not nm:
        print("❌ No name match")
        return None
    best_lap = float(nm.group(1))
    avg_lap  = float(nm.group(2))
    fastest_idx = laps.index(best_lap) + 1

    return {
        'raw_location':      loc_raw.strip(),
        'display_location':  display_loc,
        'date':              date,
        'laps':              laps,
        'best_lap':          best_lap,
        'avg_lap':           avg_lap,
        'fastest_lap_num':   fastest_idx
    }

# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('imap_login'))

@app.route('/imap_login', methods=['GET','POST'])
def imap_login():
    if request.method=='POST':
        try:
            session.clear()
            session['k1_name']    = request.form['k1_name']
            usern = request.form['email_user']
            dom   = request.form['email_domain']
            full_email = f"{usern}@{dom}"
            session['email']      = full_email
            session['imap_server']= request.form['imap_server']
            session['imap_port']  = int(request.form['imap_port'])
            session['password']   = request.form['password']

            # validate IMAP creds
            with imaplib.IMAP4_SSL(session['imap_server'], session['imap_port']) as M:
                M.login(full_email, session['password'])
                M.select('INBOX')

            # new vs returning
            if User.query.filter_by(email=full_email).first():
                return redirect(url_for('profile_found'))
            else:
                return redirect(url_for('profile_setup'))

        except Exception as e:
            flash(f"Login failed: {e}", 'error')

    return render_template('imap_login.html')

@app.route('/profile_setup', methods=['GET','POST'])
def profile_setup():
    if 'email' not in session:
        flash("Please log in first", 'error')
        return redirect(url_for('imap_login'))

    if request.method=='POST':
        try:
            pic_path = ''
            if 'profile_pic_file' in request.files:
                f = request.files['profile_pic_file']
                if f and allowed_file(f.filename):
                    fn = secure_filename(f.filename)
                    save_to = os.path.join(app.config['UPLOAD_FOLDER'], fn)
                    f.save(save_to)
                    pic_path = save_to

            user = User(
                username=request.form['username'],
                email=session['email'],
                profile_pic=pic_path,
                leaderboard_consent=('consent' in request.form)
            )
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('import_results'))
        except Exception as e:
            flash(f"Error: {e}", 'error')

    return render_template('profile_setup.html')

@app.route('/profile_found', methods=['GET','POST'])
def profile_found():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash("User not found, please log in again", 'error')
        return redirect(url_for('imap_login'))

    if request.method=='POST':
        return redirect(url_for('import_loading'))

    total = sum(len(t.sessions) for t in user.tracks)
    return render_template(
        'profile_found.html',
        username=user.username,
        profile_pic=user.profile_pic,
        consent=user.leaderboard_consent,
        total_races=total
    )


@app.route('/import_loading')
def import_loading():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    return render_template('import_loading.html')

@app.route('/import_results')
def import_results():
    if 'email' not in session:
        return jsonify(status='error', message='Not logged in')

    try:
        M = imaplib.IMAP4_SSL(session['imap_server'], session['imap_port'])
        M.login(session['email'], session['password'])
        M.select('INBOX')

        # search
        typ, msgs = M.search(
            None,
            '(OR FROM "member@from.k1speed.com" FROM "noreply@from.k1speed.com") SUBJECT "Your Race Results"'
        )
        if typ!='OK':
            return jsonify(status='error', message='Email search failed')

        ids = msgs[0].split()
        user = User.query.filter_by(email=session['email']).first()
        imported = 0

        for eid in ids:
            # fetch bytes
            typ, data = M.fetch(eid, '(RFC822)')
            raw = None
            if data and isinstance(data[0], tuple):
                raw = data[0][1]
            else:
                # fallback
                typ, data = M.fetch(eid, '(BODY.PEEK[])')
                if data and isinstance(data[0], tuple):
                    raw = data[0][1]

            if not raw:
                continue

            msg = BytesParser(policy=default).parsebytes(raw)
            rd = parse_email(msg, session['k1_name'])
            if not rd:
                continue

            # store track
            track = Track.query.filter_by(
                raw_name=rd['raw_location'], user_id=user.id
            ).first()
            if not track:
                track = Track(
                    raw_name=rd['raw_location'],
                    display_name=rd['display_location'],
                    user_id=user.id
                )
                db.session.add(track)
                db.session.commit()

            # store session
            if not Session.query.filter_by(track_id=track.id, date=rd['date']).first():
                s = Session(
                    date=rd['date'],
                    total_laps=len(rd['laps']),
                    best_lap=rd['best_lap'],
                    avg_lap=rd['avg_lap'],
                    fastest_lap_num=rd['fastest_lap_num'],
                    lap_data=str(rd['laps']),
                    track_id=track.id
                )
                db.session.add(s)
                imported += 1

        db.session.commit()
        M.close()
        M.logout()
        return jsonify(status='success', imported=imported)

    except Exception as e:
        return jsonify(status='error', message=str(e))

@app.route('/results')
def results():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('imap_login'))

    data = {}
    for t in user.tracks:
        if t.sessions:
            best = min(t.sessions, key=lambda s: s.best_lap)
            first = min(t.sessions, key=lambda s: s.date)
            data[t.display_name] = {
                'raw_name'  : t.raw_name,
                'sessions'  : len(t.sessions),
                'first_date': first.date.strftime('%Y-%m-%d'),
                'best_lap'  : f"{best.best_lap:.3f}",
                'best_date' : best.date.strftime('%Y-%m-%d')
            }

    return render_template(
        'results.html',
        username=user.username,
        profile_pic=user.profile_pic,
        tracks=data
    )

@app.route('/track/<track_name>')
def track_detail(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    t = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    sessions, dates, bests = [], [], []
    for s in t.sessions:
        laps = eval(s.lap_data)
        sessions.append({
            'date': s.date.strftime('%Y-%m-%d %H:%M'),
            'total_laps': s.total_laps,
            'best_lap': f"{s.best_lap:.3f}",
            'avg_lap': f"{s.avg_lap:.3f}",
            'fastest_lap_num': s.fastest_lap_num,
            'laps': laps
        })
        dates.append(s.date.strftime('%Y-%m-%d'))
        bests.append(s.best_lap)

    # chart improvements...
    improvement_dates, improvement_laps = [], []
    best_so_far = float('inf')
    for s in sorted(t.sessions, key=lambda x: x.date):
        if s.best_lap < best_so_far:
            best_so_far = s.best_lap
            improvement_dates.append(s.date.strftime('%Y-%m-%d %H:%M'))
            improvement_laps.append(s.best_lap)

    chart_data = dict(
        dates=[d['date'] for d in sessions],
        best_laps=bests,
        improvement_dates=improvement_dates,
        improvement_laps=improvement_laps
    )

    return render_template(
        'track.html',
        track_name=t.display_name,
        sessions=sessions,
        chart_data=chart_data,
        username=user.username,
        profile_pic=user.profile_pic
    )

@app.route('/download/<track_name>.csv')
def download(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    t = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    out = StringIO()
    w = csv.writer(out)
    w.writerow(
        ['Date','Total Laps','Best Lap','Avg Lap','Fastest Lap #']
        + [f'Lap {i}' for i in range(1,17)]
    )
    for s in t.sessions:
        laps = eval(s.lap_data)
        row = [
            s.date.strftime('%Y-%m-%d %H:%M'),
            s.total_laps, s.best_lap, s.avg_lap, s.fastest_lap_num
        ] + laps[:16]
        w.writerow(row)

    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{t.display_name}.csv"'}
    )

@app.route('/leaderboard')
def leaderboard():
    tracks = [r[0] for r in db.session.query(Track.display_name).distinct().all()]
    return render_template('leaderboard.html', tracks=tracks)

@app.route('/leaderboard/<track_name>')
def track_leaderboard(track_name):
    all_tracks = Track.query.filter_by(display_name=track_name).all()
    best_laps, most_sessions = [], {}

    for t in all_tracks:
        u = t.user
        if not u.leaderboard_consent: continue
        if not t.sessions: continue

        # session count
        most_sessions.setdefault(u.id, {
            'username':u.username, 'profile_pic':u.profile_pic,
            'session_count':0,
            'first_date':min(s.date for s in t.sessions)
        })
        most_sessions[u.id]['session_count'] += len(t.sessions)

        # best lap
        b = min(t.sessions, key=lambda s: s.best_lap)
        best_laps.append({
            'username':u.username,
            'profile_pic':u.profile_pic,
            'best_lap':b.best_lap,
            'best_date':b.date.strftime('%Y-%m-%d')
        })

    ms_list = sorted(most_sessions.values(), key=lambda x: x['session_count'], reverse=True)
    bl_list = sorted(best_laps, key=lambda x: x['best_lap'])

    return render_template(
        'track_leaderboard.html',
        track_name=track_name,
        most_sessions=ms_list,
        best_laps=bl_list
    )

# ensure tables exist
with app.app_context():
    db.create_all()

if __name__=='__main__':
    app.run(debug=True)




@app.route('/import_loading')
def import_loading():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    return render_template('import_loading.html')

@app.route('/import_results')
def import_results():
    if 'email' not in session:
        return jsonify(status='error', message='Not logged in')

    try:
        M = imaplib.IMAP4_SSL(session['imap_server'], session['imap_port'])
        M.login(session['email'], session['password'])
        M.select('INBOX')

        # search
        typ, msgs = M.search(
            None,
            '(OR FROM "member@from.k1speed.com" FROM "noreply@from.k1speed.com") SUBJECT "Your Race Results"'
        )
        if typ!='OK':
            return jsonify(status='error', message='Email search failed')

        ids = msgs[0].split()
        user = User.query.filter_by(email=session['email']).first()
        imported = 0

        for eid in ids:
            # fetch bytes
            typ, data = M.fetch(eid, '(RFC822)')
            raw = None
            if data and isinstance(data[0], tuple):
                raw = data[0][1]
            else:
                # fallback
                typ, data = M.fetch(eid, '(BODY.PEEK[])')
                if data and isinstance(data[0], tuple):
                    raw = data[0][1]

            if not raw:
                continue

            msg = BytesParser(policy=default).parsebytes(raw)
            rd = parse_email(msg, session['k1_name'])
            if not rd:
                continue

            # store track
            track = Track.query.filter_by(
                raw_name=rd['raw_location'], user_id=user.id
            ).first()
            if not track:
                track = Track(
                    raw_name=rd['raw_location'],
                    display_name=rd['display_location'],
                    user_id=user.id
                )
                db.session.add(track)
                db.session.commit()

            # store session
            if not Session.query.filter_by(track_id=track.id, date=rd['date']).first():
                s = Session(
                    date=rd['date'],
                    total_laps=len(rd['laps']),
                    best_lap=rd['best_lap'],
                    avg_lap=rd['avg_lap'],
                    fastest_lap_num=rd['fastest_lap_num'],
                    lap_data=str(rd['laps']),
                    track_id=track.id
                )
                db.session.add(s)
                imported += 1

        db.session.commit()
        M.close()
        M.logout()
        return jsonify(status='success', imported=imported)

    except Exception as e:
        return jsonify(status='error', message=str(e))

@app.route('/results')
def results():
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('imap_login'))

    data = {}
    for t in user.tracks:
        if t.sessions:
            best = min(t.sessions, key=lambda s: s.best_lap)
            first = min(t.sessions, key=lambda s: s.date)
            data[t.display_name] = {
                'raw_name'  : t.raw_name,
                'sessions'  : len(t.sessions),
                'first_date': first.date.strftime('%Y-%m-%d'),
                'best_lap'  : f"{best.best_lap:.3f}",
                'best_date' : best.date.strftime('%Y-%m-%d')
            }

    return render_template(
        'results.html',
        username=user.username,
        profile_pic=user.profile_pic,
        tracks=data
    )

@app.route('/track/<track_name>')
def track_detail(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    t = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    sessions, dates, bests = [], [], []
    for s in t.sessions:
        laps = eval(s.lap_data)
        sessions.append({
            'date': s.date.strftime('%Y-%m-%d %H:%M'),
            'total_laps': s.total_laps,
            'best_lap': f"{s.best_lap:.3f}",
            'avg_lap': f"{s.avg_lap:.3f}",
            'fastest_lap_num': s.fastest_lap_num,
            'laps': laps
        })
        dates.append(s.date.strftime('%Y-%m-%d'))
        bests.append(s.best_lap)

    # chart improvements...
    improvement_dates, improvement_laps = [], []
    best_so_far = float('inf')
    for s in sorted(t.sessions, key=lambda x: x.date):
        if s.best_lap < best_so_far:
            best_so_far = s.best_lap
            improvement_dates.append(s.date.strftime('%Y-%m-%d %H:%M'))
            improvement_laps.append(s.best_lap)

    chart_data = dict(
        dates=[d['date'] for d in sessions],
        best_laps=bests,
        improvement_dates=improvement_dates,
        improvement_laps=improvement_laps
    )

    return render_template(
        'track.html',
        track_name=t.display_name,
        sessions=sessions,
        chart_data=chart_data,
        username=user.username,
        profile_pic=user.profile_pic
    )

@app.route('/download/<track_name>.csv')
def download(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))
    user = User.query.filter_by(email=session['email']).first()
    t = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    out = StringIO()
    w = csv.writer(out)
    w.writerow(
        ['Date','Total Laps','Best Lap','Avg Lap','Fastest Lap #']
        + [f'Lap {i}' for i in range(1,17)]
    )
    for s in t.sessions:
        laps = eval(s.lap_data)
        row = [
            s.date.strftime('%Y-%m-%d %H:%M'),
            s.total_laps, s.best_lap, s.avg_lap, s.fastest_lap_num
        ] + laps[:16]
        w.writerow(row)

    return Response(
        out.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename="{t.display_name}.csv"'}
    )

@app.route('/leaderboard')
def leaderboard():
    tracks = [r[0] for r in db.session.query(Track.display_name).distinct().all()]
    return render_template('leaderboard.html', tracks=tracks)

@app.route('/leaderboard/<track_name>')
def track_leaderboard(track_name):
    all_tracks = Track.query.filter_by(display_name=track_name).all()
    best_laps, most_sessions = [], {}

    for t in all_tracks:
        u = t.user
        if not u.leaderboard_consent: continue
        if not t.sessions: continue

        # session count
        most_sessions.setdefault(u.id, {
            'username':u.username, 'profile_pic':u.profile_pic,
            'session_count':0,
            'first_date':min(s.date for s in t.sessions)
        })
        most_sessions[u.id]['session_count'] += len(t.sessions)

        # best lap
        b = min(t.sessions, key=lambda s: s.best_lap)
        best_laps.append({
            'username':u.username,
            'profile_pic':u.profile_pic,
            'best_lap':b.best_lap,
            'best_date':b.date.strftime('%Y-%m-%d')
        })

    ms_list = sorted(most_sessions.values(), key=lambda x: x['session_count'], reverse=True)
    bl_list = sorted(best_laps, key=lambda x: x['best_lap'])

    return render_template(
        'track_leaderboard.html',
        track_name=track_name,
        most_sessions=ms_list,
        best_laps=bl_list
    )

# ensure tables exist
with app.app_context():
    db.create_all()

if __name__=='__main__':
    app.run(debug=True)
