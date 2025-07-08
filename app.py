import os
import re
import imaplib
import csv
from datetime import datetime
import statistics
from io import StringIO
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash,
    jsonify, Response
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename

# for parsing raw email bytes
from email.parser import BytesParser
from email.policy import default
# --- Flask + DB setup ---
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////data/data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Email Provider Configuration ---
EMAIL_PROVIDER_IMAP = {
    # Google
    'gmail.com': {'server': 'imap.gmail.com', 'port': 993},
    'googlemail.com': {'server': 'imap.gmail.com', 'port': 993},
    
    # Microsoft
    'outlook.com': {'server': 'outlook.office365.com', 'port': 993},
    'hotmail.com': {'server': 'outlook.office365.com', 'port': 993},
    'live.com': {'server': 'outlook.office365.com', 'port': 993},
    'msn.com': {'server': 'outlook.office365.com', 'port': 993},
    
    # Yahoo
    'yahoo.com': {'server': 'imap.mail.yahoo.com', 'port': 993},
    'ymail.com': {'server': 'imap.mail.yahoo.com', 'port': 993},
    
    # Apple
    'icloud.com': {'server': 'imap.mail.me.com', 'port': 993},
    'me.com': {'server': 'imap.mail.me.com', 'port': 993},
    'mac.com': {'server': 'imap.mail.me.com', 'port': 993},
    
    # AOL
    'aol.com': {'server': 'imap.aol.com', 'port': 993},
    
    # ProtonMail (requires bridge)
    'protonmail.com': {'server': '127.0.0.1', 'port': 1143},
    'proton.me': {'server': '127.0.0.1', 'port': 1143},
    
    # Default fallback (for custom domains)
    'default': {'server': 'imap.{domain}', 'port': 993}
}

# --- Track-specific lap time cutoffs ---
LAP_TIME_CUTOFFS = {
    'Burbank': 23.2,
    'Thousand Oaks': 27.5
}


# --- Models ---
class User(db.Model):
    id                  = db.Column(db.Integer, primary_key=True)
    username            = db.Column(db.String(80), nullable=False)
    email               = db.Column(db.String(120), unique=True, nullable=False)
    leaderboard_consent = db.Column(db.Boolean, default=False)
    tracks              = db.relationship('Track', backref='user', lazy=True)

class Track(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    raw_name     = db.Column(db.String(80), nullable=False)
    display_name = db.Column(db.String(80), nullable=False)
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
def extract_email_body(msg):
    """Safely pull out first text/plain or text/html part."""
    if msg.is_multipart():
        for part in msg.walk():
            if 'attachment' in str(part.get('Content-Disposition', '')):
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

def filter_laps_by_cutoff(display_location, laps):
    cutoff = LAP_TIME_CUTOFFS.get(display_location)
    if not cutoff:
        return laps  # No cutoff defined, keep all laps
    return [lap for lap in laps if lap >= cutoff]


def track_image_filename(raw_name):
    """Return the standardized track image filename."""
    name = raw_name.strip().lower().replace(' ', '_')
    return f"{name}.jpeg"


def parse_email(msg, k1_name):
    """Parse a K1 speed results email into structured data."""
    body = extract_email_body(msg)
    if not body:
        print("⚠️ Empty body")
        return None

    # strip HTML, normalize whitespace
    body = re.sub(r'<br\s*/?>', ' ', body, flags=re.IGNORECASE)
    body = re.sub(r'<[^>]+>', ' ', body)
    text = re.sub(r'\s+', ' ', body).strip()

    # header pattern
    m = re.search(
        r"LAPTIMES\s*-\s*([A-Za-z0-9\s]+?)\s+(\d{2}/\d{2}/\d{2})\s+(\d{1,2}:\d{2}\s[AP]M)",
        text, re.IGNORECASE
    )
    if not m:
        print("❌ No header")
        return None
    loc_raw, date_str, time_str = m.groups()
    date = datetime.strptime(f"{date_str} {time_str}", "%m/%d/%y %I:%M %p")
    display_loc = re.sub(r"\bT(\d)\b", r"Track \1", loc_raw.strip().title())

    # extract lap times
    laps = [float(x) for x in re.findall(r"\(\d+\)\s*([\d.]+)", text)]
    laps = filter_laps_by_cutoff(display_loc, laps)

    if len(laps) < 1 or min(laps) > 300:
        print("❌ Invalid lap data")
        return None

    # find your best/avg by name line
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
        'raw_location': loc_raw.strip(),
        'display_location': display_loc,
        'date': date,
        'laps': laps,
        'best_lap': best_lap,
        'avg_lap': avg_lap,
        'fastest_lap_num': fastest_idx
    }


# --- Routes ---
@app.route('/')
def home():
    return redirect(url_for('imap_login'))


@app.route('/imap_login', methods=['GET','POST'])
def imap_login():
    if request.method == 'POST':
        try:
            session.clear()
            session['k1_name'] = request.form['k1_name']
            email = request.form['email'].strip()
            
            # Validate email format
            if '@' not in email:
                flash("Please enter a valid email address", 'error')
                return redirect(url_for('imap_login'))
            
            session['email'] = email
            domain = email.split('@')[-1].lower()
            
            # Handle custom IMAP settings if provided
            if request.form.get('imap_server'):
                session['imap_server'] = request.form['imap_server'].strip()
                try:
                    session['imap_port'] = int(request.form.get('imap_port', 993))
                except ValueError:
                    flash("IMAP port must be a number", 'error')
                    return redirect(url_for('imap_login'))
            else:
                # Auto-detect configuration
                provider_config = EMAIL_PROVIDER_IMAP.get(domain, EMAIL_PROVIDER_IMAP['default'])
                session['imap_server'] = provider_config['server'].format(domain=domain)
                session['imap_port'] = provider_config['port']
            
            if not request.form['password']:
                flash("Password cannot be empty", 'error')
                return redirect(url_for('imap_login'))
                
            session['password'] = request.form['password']

            # Test IMAP connection
            try:
                with imaplib.IMAP4_SSL(session['imap_server'], session['imap_port']) as M:
                    M.login(session['email'], session['password'])
                    M.select('INBOX')
            except imaplib.IMAP4.error as e:
                error_msg = str(e)
                if "Invalid credentials" in error_msg:
                    flash("Login failed: Wrong email or password", 'error')
                elif "connection refused" in error_msg.lower():
                    flash(f"Couldn't connect to {session['imap_server']}. Try manual IMAP settings.", 'error')
                else:
                    flash(f"Email error: {error_msg}", 'error')
                return redirect(url_for('imap_login'))

            # Check if user exists
            user = User.query.filter_by(email=session['email']).first()
            if user:
                return redirect(url_for('profile_found'))
            return redirect(url_for('profile_setup'))

        except Exception as e:
            flash(f"Error: {str(e)}", 'error')
            app.logger.error(f"Login error: {str(e)}")
            return redirect(url_for('imap_login'))

    return render_template('imap_login.html')


@app.route('/profile_setup', methods=['GET','POST'])
def profile_setup():
    if 'email' not in session:
        flash("Please log in first", "error")
        return redirect(url_for('imap_login'))

    # Try to load an existing user (if they've already set up once)
    existing = User.query.filter_by(email=session['email']).first()

    if request.method == 'POST':
        try:
            if existing:
                # Update the existing record
                existing.username            = request.form['username']
                existing.leaderboard_consent = ('consent' in request.form)
                db.session.commit()
            else:
                # Create a new one
                new_user = User(
                    username=request.form['username'],
                    email=session['email'],
                    leaderboard_consent=('consent' in request.form)
                )
                db.session.add(new_user)
                db.session.commit()

            return redirect(url_for('results'))

        except Exception as e:
            flash(f"Error saving profile: {e}", "error")

    return render_template(
        'profile_setup.html',
        username = existing.username if existing else "",
        consent  = existing.leaderboard_consent if existing else False
    )


@app.route('/profile_found', methods=['GET','POST'])
def profile_found():
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        flash("User not found, please log in again", 'error')
        return redirect(url_for('imap_login'))

    if request.method == 'POST':
        return redirect(url_for('results'))

    total = sum(len(t.sessions) for t in user.tracks)
    return render_template('profile_found.html',
                           username=user.username,
                           consent=user.leaderboard_consent,
                           total_races=total)


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
        # 1) Log in to IMAP
        M = imaplib.IMAP4_SSL(session['imap_server'], session['imap_port'])
        M.login(session['email'], session['password'])
        M.select('INBOX')

        # 2) Find the user & latest imported session date
        user = User.query.filter_by(email=session['email']).first()

        latest_row = (
            db.session
              .query(Session.date)
              .join(Track, Track.id == Session.track_id)
              .filter(Track.user_id == user.id)
              .order_by(Session.date.desc())
              .first()
        )
        if latest_row:
            last_dt = latest_row[0]
            since_str = last_dt.strftime("%d-%b-%Y")  # e.g. "25-May-2025"
        else:
            since_str = None

        # 3) Build IMAP search criteria
        if since_str:
            search_criteria = (
                f'(SINCE {since_str}) '
                '(OR FROM "member@from.k1speed.com" '
                'FROM "noreply@from.k1speed.com") '
                'SUBJECT "Your Race Results"'
            )
        else:
            search_criteria = (
                '(OR FROM "member@from.k1speed.com" '
                'FROM "noreply@from.k1speed.com") '
                'SUBJECT "Your Race Results"'
            )

        typ, msgs = M.search(None, search_criteria)
        if typ != 'OK':
            return jsonify(status='error', message='Email search failed')

        ids = msgs[0].split()
        imported = 0

        # 4) Loop through returned message IDs exactly as before,
        #    skipping duplicates by checking Session(track_id, date).
        for eid in ids:
            typ, data = M.fetch(eid, '(RFC822)')
            raw = None
            if data and isinstance(data[0], tuple):
                raw = data[0][1]
            else:
                typ, data = M.fetch(eid, '(BODY.PEEK[])')
                if data and isinstance(data[0], tuple):
                    raw = data[0][1]

            if not raw:
                continue

            msg = BytesParser(policy=default).parsebytes(raw)
            rd  = parse_email(msg, session['k1_name'])
            if not rd:
                continue

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

            # Only insert if that exact (track_id, date) isn’t already in the DB
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

    tracks_data = {}
    all_sessions = []
    for t in user.tracks:
        if not t.sessions:
            continue
        best    = min(t.sessions, key=lambda s: s.best_lap)
        first   = min(t.sessions, key=lambda s: s.date)
        image_file = track_image_filename(t.raw_name)
        image_path = os.path.join(app.root_path, 'static', 'img', 'tracks', image_file)
        tracks_data[t.display_name] = {
            'raw_name'   : t.raw_name,
            'image_file' : image_file,
            'has_image'  : os.path.exists(image_path),
            'sessions'   : len(t.sessions),
            'first_date' : first.date.strftime('%Y-%m-%d'),
            'best_lap'   : f"{best.best_lap:.3f}",
            'best_date'  : best.date.strftime('%Y-%m-%d')
        }
        all_sessions.extend(t.sessions)

    sorted_tracks = sorted(
        tracks_data.items(),
        key=lambda x: x[1]['sessions'],
        reverse=True
    )

    total_races = len(all_sessions)

    racer_since = None
    if all_sessions:
        racer_since = min(all_sessions, key=lambda s: s.date).date.strftime('%Y-%m-%d')

    favourite_track = None
    if sorted_tracks:
        favourite_track = sorted_tracks[0][0]

    # favourite day of week
    fav_day = None
    if all_sessions:
        dow_counts = [0]*7
        for s in all_sessions:
            dow_counts[s.date.weekday()] += 1
        import calendar
        fav_day = calendar.day_name[dow_counts.index(max(dow_counts))]

    return render_template(
        'results.html',
        username=user.username,
        tracks=sorted_tracks,
        total_races=total_races,
        racer_since=racer_since,
        favourite_track=favourite_track,
        favourite_day=fav_day
    )


@app.route('/visit_data')
def visit_data():
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    user = User.query.filter_by(email=session['email']).first()
    if not user:
        return redirect(url_for('imap_login'))

    favourite_track = None
    all_sessions = []
    if user.tracks:
        favourite_track = max(user.tracks, key=lambda t: len(t.sessions)).display_name
        for t in user.tracks:
            all_sessions.extend(t.sessions)

    visit_data = {}
    for t in user.tracks:
        dates = [s.date.strftime('%Y-%m-%dT%H:%M:%S') for s in sorted(t.sessions, key=lambda s: s.date)]
        if dates:
            visit_data[t.display_name] = dates

    racer_since = None
    fav_day = None
    if all_sessions:
        racer_since = min(all_sessions, key=lambda s: s.date).date.strftime('%Y-%m-%d')
        import calendar
        dow_counts = [0]*7
        for s in all_sessions:
            dow_counts[s.date.weekday()] += 1
        fav_day = calendar.day_name[dow_counts.index(max(dow_counts))]

    total_races = len(all_sessions)

    return render_template('visit_data.html',
                           favourite_track=favourite_track,
                           visit_data=visit_data,
                           username=user.username,
                           total_races=total_races,
                           racer_since=racer_since,
                           favourite_day=fav_day)


@app.route('/track/<track_name>')
def track_detail(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    user = User.query.filter_by(email=session['email']).first()
    t    = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    sessions, dates, bests, date_times = [], [], [], []
    for s in sorted(t.sessions, key=lambda x: x.date):
        lap_list = eval(s.lap_data or '[]')
        sessions.append({
            'id': s.id,
            'date': s.date.strftime('%Y-%m-%d %H:%M'),
            'total_laps': s.total_laps,
            'best_lap': f"{s.best_lap:.3f}",
            'avg_lap': f"{s.avg_lap:.3f}",
            'fastest_lap_num': s.fastest_lap_num,
            'laps': lap_list
        })
        dates.append(s.date.strftime('%Y-%m-%d'))
        date_times.append(s.date.strftime('%Y-%m-%d %H:%M'))
        bests.append(s.best_lap)

    drift_cutoff = 0
    if bests:
        drift_cutoff = statistics.median(bests) + 7

    improvement_dates, improvement_laps = [], []
    best_so_far = float('inf')
    for s in sorted(t.sessions, key=lambda x: x.date):
        if s.best_lap < best_so_far:
            best_so_far = s.best_lap
            improvement_dates.append(s.date.strftime('%Y-%m-%d %H:%M'))
            improvement_laps.append(s.best_lap)

    chart_data = {
        'dates': dates,
        'best_laps': bests,
        'improvement_dates': improvement_dates,
        'improvement_laps': improvement_laps,
        'drift_cutoff': drift_cutoff,
        'date_times': date_times
    }

    return render_template('track.html',
                           track_name=t.display_name,
                           sessions=sessions,
                           chart_data=chart_data,
                           username=user.username)

@app.route('/race/<int:session_id>')
def race_detail(session_id):
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    race_session = Session.query.get_or_404(session_id)
    if race_session.track.user.email != session['email']:
        return redirect(url_for('imap_login'))

    laps = eval(race_session.lap_data or '[]')
    user_sessions = race_session.track.sessions
    personal_best = min((s.best_lap for s in user_sessions), default=None)

    return render_template(
        'race.html',
        track_name=race_session.track.display_name,
        race_session=race_session,
        laps=laps,
        personal_best=personal_best,
        username=race_session.track.user.username
    )



@app.route('/download/<track_name>.csv')
def download(track_name):
    if 'email' not in session:
        return redirect(url_for('imap_login'))

    user = User.query.filter_by(email=session['email']).first()
    t    = Track.query.filter_by(raw_name=track_name, user_id=user.id).first()

    out = StringIO()
    w   = csv.writer(out)
    w.writerow(['Date','Total Laps','Best Lap','Avg Lap','Fastest Lap #']
               + [f'Lap {i}' for i in range(1,17)])

    for s in t.sessions:
        laps = eval(s.lap_data or '[]')
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
    # Pull distinct display_names, alphabetically
    rows = (
        db.session
          .query(Track.display_name)
          .distinct()
          .order_by(Track.display_name)
          .all()
    )
    tracks = [r[0] for r in rows]
    return render_template('leaderboard.html', tracks=tracks)




@app.route('/leaderboard/<track_name>')
def track_leaderboard(track_name):
    all_tracks    = Track.query.filter_by(display_name=track_name).all()
    best_laps, most_sessions = [], {}

    for t in all_tracks:
        u = t.user
        if not u.leaderboard_consent or not t.sessions:
            continue

        # tally sessions
        ent = most_sessions.setdefault(u.id, {
            'username': u.username,
            'session_count': 0,
            'first_date': min(s.date for s in t.sessions)
        })
        ent['session_count'] += len(t.sessions)

        # record best lap
        b = min(t.sessions, key=lambda s: s.best_lap)
        best_laps.append({
            'username': u.username,
            'best_lap': b.best_lap,
            'best_date': b.date.strftime('%Y-%m-%d')
        })

    ms_list = sorted(most_sessions.values(), key=lambda x: x['session_count'], reverse=True)
    bl_list = sorted(best_laps, key=lambda x: x['best_lap'])

    return render_template('track_leaderboard.html',
                           track_name=track_name,
                           most_sessions=ms_list,
                           best_laps=bl_list)


# Create tables & run
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
