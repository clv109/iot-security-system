from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, abort, Response # <--- ADDED Response
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from apscheduler.schedulers.background import BackgroundScheduler
from functools import wraps
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import subprocess
import os
import signal
import sys
import json
import re
from datetime import datetime, timedelta
import calendar
import time
import platform
import config
import pickle
import face_recognition
import cv2
import numpy as np
import sqlite3
import math
import statistics
import requests

# Imported modules for EMAIl capalibity
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# System security imports
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect

# Load envionrment variables (containing secrets/passwords)
load_dotenv("secretcredentials.env")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_SECRET_KEY")

# Secure cookie configurations
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False

csrf = CSRFProtect(app)

# Initialize security tools
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Kicks unauthenticated users to the login page

# Establish SQLite database path
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'surveillance.db')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"[INFO] Database will be located at: {db_path}")

# Initialize Database & SocketIO
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")

LOG_FILE = "security_events.log"
PID_FILE = "camera.pid"
SCRIPT_NAME = "Camera_Script.py"
IS_WINDOWS = platform.system() == "Windows"
DATASET_DIR = "dataset"
ENCODINGS_FILE = "encodings.pickle"

# Ensure dataset directory exists
if not os.path.exists(DATASET_DIR):
    os.makedirs(DATASET_DIR)

# --Defining Database Tables--

class DetectionEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    status = db.Column(db.String(50), nullable=False)
    image_path = db.Column(db.String(200))
    person_name = db.Column(db.String(100), default="Unknown") # Tracks excatly who was seen
    duration_seconds = db.Column(db.Float, default=0.0)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'status': self.status,
            'image_path': self.image_path,
            'person_name': self.person_name, 
            'duration_seconds': self.duration_seconds 
        }

class AlertLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    method = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'method': self.method,
            'recipient': self.recipient,
            'event_type': self.event_type,
            'status': self.status
        }

class AuthorizedUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_added = db.Column(db.DateTime, default=datetime.now)
    image_count = db.Column(db.Integer, default=0)
    notes = db.Column(db.String(255), default="Active Authorization")

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'date_added': self.date_added.strftime('%Y-%m-%d %H:%M:%S'),
            'image_count': self.image_count,
            'notes': self.notes
        }

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    level = db.Column(db.String(20), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    details = db.Column(db.String(255))

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'level': self.level,
            'source': self.source,
            'event_type': self.event_type,
            'message': self.message,
            'details': self.details
        }

# Audit Log Table to record sensitive actions
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    username = db.Column(db.String(50), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.String(255))

    def to_dict(self): 
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'username': self.username,
            'action': self.action,
            'details': self.details
        }


# System report archive table for emails
class SystemReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    coverage_date = db.Column(db.Date, nullable=False)       
    report_type = db.Column(db.String(50), nullable=False)  
    content = db.Column(db.Text, nullable=False)             
    emailed_status = db.Column(db.Boolean, default=False)    

    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'coverage_date': self.coverage_date.strftime('%Y-%m-%d'),
            'report_type': self.report_type,
            'content': json.loads(self.content), 
            'emailed_status': self.emailed_status
        }

# User authentication table
class User(db.Model, UserMixin): 
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) #hashed to ensure password is encrypted
    role = db.Column(db.String(20), default="Viewer", nullable=False) # Two roles: either "Admin" or "viewer"

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'role': self.role
        }


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in or not
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        
        if current_user.role != "Admin":
            log_system_event("WARNING", "Access Denied", f"Viewer '{current_user.username}' attempted to use an Admin control.")
            abort(403)

        #If user is logged in and is Admin, then they pass
        return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper function to log system events
def log_system_event(level, event_type, message, details=None):
    try:
        log_entry = SystemLog(
            level=level,
            source="Backend",
            event_type=event_type,
            message=message,
            details=details
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to write system log: {e}")

# Helper function for SQLite database audit logging 
def log_user_action(action, details=None):
    '''Records what a human user did in the dashboard.'''
    try:
        
        user_name = current_user.username if current_user.is_authenticated else "System"

        audit_entry = AuditLog(
            username=user_name,
            action=action,
            details=details
        )
        db.session.add(audit_entry)
        db.session.commit()
    except Exception as e:
        print(f"Failed to write audit log: {e}")

# --ROUTES--

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Skip this route if user is already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Look up the user by name
        user = User.query.filter_by(username=username).first()

        # Run the inputted password through the math and compare to DB hash
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user) #built in function on Flask-login that authenticates a user and recognizes them
            log_system_event("INFO", "Login", f"User '{username}' authenticated successfully.")
            log_user_action("Login", "User logged into the dashboard.") 
            return redirect(url_for('dashboard'))
        else:
            log_system_event("WARNING", "Failed Login", f"Failed attempt for username '{username}'.")

            # Log IP to flask_auth.log for fail2ban purposes
            client_ip = request.remote_addr
            with open("flask_auth.log", "a") as f:
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"{now_str} [Auth Failure] IP: {client_ip} tried to log in as '{username}'\n")

            return render_template('Login_Page.html', error="Invalid username or password")

    return render_template('Login_Page.html')

@app.route('/logout')
@login_required
def logout():
    log_system_event("INFO", "Logout", f"User '{current_user.username}' logged out.")
    log_user_action("Logout", "User logged out of the dashboard.") 
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('Best_Dashboard.html')

@app.route('/livecam')
@login_required
def camera_feed():
    pi_ip = request.host.split(':')[0]
    return render_template('Live_Cam_Feed.html', pi_ip=pi_ip)

# Secure video stream
@app.route('/video_stream')
@login_required
def video_stream():
    """Proxies the unencrypted local camera stream through Flask's secure HTTPS connection"""
    try:
        # Grab the local stream from the camera script 
        req = requests.get('http://127.0.0.1:5001/stream.mjpg', stream=True, timeout=5)
        return Response(req.iter_content(chunk_size=1024), mimetype=req.headers.get('Content-Type', 'multipart/x-mixed-replace; boundary=FRAME'))
    except Exception as e:
        print(f"[ERROR] Proxy stream failed: {e}")
        abort(502)


@app.route('/api/trigger_alert', methods=['POST'])
@csrf.exempt
def trigger_alert_bridge():
    try:
        data = request.json
        socketio.emit('security_event', data)
        return jsonify(status="success")
    except Exception as e:
        return jsonify(status="error", message=str(e)), 500

# Fetch audit logs (restricted to admin only access)
@app.route('/api/audit_logs')
@login_required
@admin_required 
def get_audit_logs():
    """Fetches the human audit trail for the dashboard."""
    
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    
    return jsonify([log.to_dict() for log in logs])



def kill_process_by_name(name):
    try:
        if IS_WINDOWS:
            cmd = f"wmic process where \"name='python.exe' and commandline like '%{name}%'\" call terminate"
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-9", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"Error during cleanup: {e}")

def is_running():
    if not os.path.exists(PID_FILE):
        return False
    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        if IS_WINDOWS:
            output = subprocess.check_output(f"tasklist /fi \"PID eq {pid}\"", shell=True).decode()
            return str(pid) in output
        else:
            os.kill(pid, 0)
            return True
    except (OSError, ValueError, subprocess.CalledProcessError):
        return False

def get_encryption_key():
    """Loads the master encryption key from the environment vault."""
    biometric_key = os.getenv("BIOMETRIC_KEY")
    if biometric_key:
        return biometric_key.encode('utf-8') # Convert string to bytes for Fernet

    print("[WARNING] BIOMETRIC_KEY not found in vault! Biometrics will not be encrypted.")
    return None

# --System Control Routes--

@app.route('/system_status')
@login_required
def system_status():
    if is_running():
        return jsonify(status="running")
    else:
        if os.path.exists(PID_FILE):
            try:
                os.remove(PID_FILE)
            except:
                pass
        return jsonify(status="stopped")

@app.route('/start_system', methods=['POST'])
@login_required
@admin_required
def start_system():
    if is_running():
        return jsonify(status="error", message="System is already running")

    try:
        kill_process_by_name(SCRIPT_NAME)
        time.sleep(0.5)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{now}] SYSTEM STARTED manually via Dashboard"

        with open(LOG_FILE, "a") as f:
            f.write(log_msg + "\n")

        with open("system_debug.txt", "w") as debug_log:
            if IS_WINDOWS:
                proc = subprocess.Popen(
                    [sys.executable, SCRIPT_NAME],
                    stdout=debug_log,
                    stderr=debug_log,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                )
            else:
                proc = subprocess.Popen(
                    [sys.executable, SCRIPT_NAME],
                    stdout=debug_log,
                    stderr=debug_log,
                    preexec_fn=os.setsid
                )

        with open(PID_FILE, "w") as f:
            f.write(str(proc.pid))

        log_system_event("INFO", "Startup", "Camera process started manually", f"PID: {proc.pid}")
        log_user_action("Armed System", "Manually started the camera feed via dashboard.") 

        socketio.emit('security_event', {'message': log_msg, 'priority': 'INFO'})

        return jsonify(status="success", message=f"Security System Started at {now}")
    except Exception as e:
        log_system_event("ERROR", "Startup Failed", str(e))
        return jsonify(status="error", message=str(e))

@app.route('/stop_system', methods=['POST'])
@login_required
@admin_required
def stop_system():
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{now}] SYSTEM STOPPED manually via Dashboard"

        if os.path.exists(PID_FILE):
            try:
                with open(PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                if IS_WINDOWS:
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)])
                else:
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                os.remove(PID_FILE)
            except:
                pass

        kill_process_by_name(SCRIPT_NAME)

        with open(LOG_FILE, "a") as f:
            f.write(log_msg + "\n")

        log_system_event("INFO", "Shutdown", "Camera process stopped manually")
        log_user_action("Disarmed System", "Manually stopped the camera feed via dashboard.") 

        socketio.emit('security_event', {'message': log_msg, 'priority': 'INFO'})

        return jsonify(status="success", message=f"Stopped at {now}")
    except Exception as e:
        log_system_event("ERROR", "Shutdown Failed", str(e))
        return jsonify(status="error", message=f"Error stopping: {str(e)}")

# --Logging Routes--

@app.route('/get_security_logs')
@login_required
def get_security_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify(logs=["No activity yet..."], total_lines=0)
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return jsonify(logs=lines[-20:], total_lines=len(lines))
    except Exception as e:
        return jsonify(logs=[f"Error reading logs: {str(e)}"], total_lines=0)

@app.route('/get_full_logs')
@login_required
def get_full_logs():
    if not os.path.exists(LOG_FILE):
        return jsonify(logs=["No history found."])
    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
        return jsonify(logs=lines[::-1])
    except Exception as e:
        return jsonify(logs=[f"Error reading history: {str(e)}"])

@app.route('/clear_logs', methods=['POST'])
@login_required
@admin_required
def clear_logs():
    try:
        with open(LOG_FILE, "w") as f:
            f.write(f"--- LOG CLEARED MANUALLY ---\n")
        log_user_action("Cleared System Logs", "Wiped the main system history file.") 
        return jsonify(status="success", message="Logs cleared.")
    except Exception as e:
        return jsonify(status="error", message=str(e))

# --Detection analytics API--
@app.route('/api/stats/detections')
@login_required
def get_detection_stats():
    try:
        start_date = datetime(2026, 3, 12)
        events = DetectionEvent.query.filter(DetectionEvent.timestamp >= start_date).order_by(DetectionEvent.timestamp.asc()).all()

        from collections import defaultdict

        stats = defaultdict(lambda: {'auth': 0, 'unauth': 0})

        for e in events:
            time_str = e.timestamp.strftime('%Y-%m-%dT%H:%M:00')

            if "Unauthorized" in e.status:
                stats[time_str]['unauth'] = 1
            elif "Authorized" in e.status:
                stats[time_str]['auth'] = 1

        data = []
        for time_str, counts in stats.items():
            data.append({
                'time': time_str,
                'auth': counts['auth'],
                'unauth': counts['unauth']
            })

        return jsonify(status="success", data=data)
    except Exception as e:
        print(f"[ERROR] Failed to fetch stats: {e}")
        return jsonify(status="error", message=str(e))

# --Statistical anomoly baselines--

def update_statistical_baselines():
    """Calculates Mean and Standard Deviation and saves it to a JSON file for the camera to use."""
    with app.app_context():
        try:
            print("[REPORT ENGINE] Recalculating statistical traffic baselines...")
            from collections import defaultdict

            cutoff_date = datetime.now() - timedelta(days=50)

            events = DetectionEvent.query.filter(DetectionEvent.timestamp >= cutoff_date).all()
            if not events:
                return {"status": "error", "message": "Not enough data."}

            traffic_data = {
                "Weekday": defaultdict(lambda: defaultdict(int)),
                "Weekend": defaultdict(lambda: defaultdict(int))
            }
            unique_days = {"Weekday": set(), "Weekend": set()}

            for e in events:
                dt = e.timestamp
                date_key = dt.date()
                hour = dt.hour

                bucket = "Weekend" if dt.weekday() >= 5 else "Weekday"
                traffic_data[bucket][hour][date_key] += 1
                unique_days[bucket].add(date_key)

            num_weekdays = len(unique_days["Weekday"])
            num_weekends = len(unique_days["Weekend"])

            baselines = {"Weekday": {}, "Weekend": {}}

            for bucket in ["Weekday", "Weekend"]:
                num_days = len(unique_days[bucket])
                if num_days == 0: continue

                for hour in range(24):
                    counts = []
                    for d in unique_days[bucket]:
                        counts.append(traffic_data[bucket][hour].get(d, 0))

                    mean = sum(counts) / num_days
                    variance = sum((x - mean) ** 2 for x in counts) / num_days
                    std_dev = math.sqrt(variance)

                    am_pm = "AM" if hour < 12 else "PM"
                    display_h = hour if hour <= 12 else hour - 12
                    if display_h == 0: display_h = 12
                    hour_label = f"{display_h}:00 {am_pm}"

                    baselines[bucket][hour_label] = {
                        "mean_traffic": round(mean, 2),
                        "standard_deviation": round(std_dev, 2),
                        "anomaly_threshold_2SD": round(mean + (2 * std_dev), 2)
                    }

            # --Daily frequency for individuals--
            person_daily_counts = defaultdict(lambda: defaultdict(int)) # person -> date -> count
            for e in events:
                date_str = e.timestamp.strftime("%Y-%m-%d")
                name = getattr(e, 'person_name', 'Unknown') or 'Unknown'
                person_daily_counts[name][date_str] += 1

            individual_stats = {}
            total_days_in_window = 50

            for name, date_counts in person_daily_counts.items():
                days_seen = len(date_counts)
                days_unseen = total_days_in_window - days_seen

                
                counts_list = list(date_counts.values()) + [0] * days_unseen

                #Set grace period for newly registered users (3 days of data)
                if days_seen < 3 and name != "Unknown":
                     continue

                mean_val = statistics.mean(counts_list)
                sd_val = statistics.pstdev(counts_list)

                individual_stats[name] = {
                    "mean_daily_appearances": round(mean_val, 2),
                    "std_dev": round(sd_val, 2),
                    "anomaly_threshold_2SD": math.ceil(mean_val + (2 * sd_val))
                }

            # --Typical visit durations--
            person_durations = defaultdict(list)
            for e in events:
                name = getattr(e, 'person_name', 'Unknown') or 'Unknown'
                dur = getattr(e, 'duration_seconds', 0.0)
                if dur > 0:  #Ignore rows with 0.0
                    person_durations[name].append(dur)

            duration_stats = {}
            for name, d_list in person_durations.items():
                # Once again grace period with 3 recorded visits
                if len(d_list) < 3 and name != "Unknown":
                    continue

                mean_dur = statistics.mean(d_list)
                sd_dur = statistics.pstdev(d_list) if len(d_list) > 1 else 0.0

                duration_stats[name] = {
                    "mean_duration_seconds": round(mean_dur, 2),
                    "std_dev": round(sd_dur, 2),
                    "anomaly_max_duration": round(mean_dur + (2 * sd_dur), 2)
                }

            final_data = {
                "dataset_size": {
                    "total_weekdays_analyzed": num_weekdays,
                    "total_weekends_analyzed": num_weekends
                },
                "statistical_baselines": baselines,
                "individual_daily_frequency": individual_stats,
                "typical_visit_durations": duration_stats 
            }

            # Save calculations to a file in baselines.json
            with open("baselines.json", "w") as f:
                json.dump(final_data, f, indent=4)

            print("[REPORT ENGINE] Baselines successfully updated and saved to baselines.json.")
            return final_data

        except Exception as e:
            print(f"[ERROR] Failed to calculate baselines: {e}")
            return {"status": "error"}

@app.route('/api/calculate_baselines')
@login_required
def api_calculate_baselines():
    """Manual trigger from the browser to view the current baselines."""
    data = update_statistical_baselines()
    return jsonify(data)

# --Occupancy prediction--
@app.route('/api/stats/predictions')
@login_required
def get_predictions():
    try:
        start_date = datetime(2026, 3, 12)
        events = DetectionEvent.query.filter(DetectionEvent.timestamp >= start_date).all()

        from collections import defaultdict

        
        daily_hour_data = defaultdict(lambda: {
            h: {
                'auth_names': set(),
                'has_unknown_auth': False,
                'unauth_peak': 0,
                'auth_mins': set(),
                'unauth_mins': set()
            } for h in range(24)
        })

        unauth_second_counts = defaultdict(int)

        for e in events:
            dt = e.timestamp
            date_key = dt.date()
            hour = dt.hour
            minute_str = dt.strftime('%Y-%m-%d %H:%M')
            second_str = dt.strftime('%Y-%m-%d %H:%M:%S')

            p_name = getattr(e, 'person_name', 'Unknown')
            if not p_name: p_name = 'Unknown'

            if "Unauthorized" in e.status:
                daily_hour_data[date_key][hour]['unauth_mins'].add(minute_str)

                unauth_second_counts[second_str] += 1
                if unauth_second_counts[second_str] > daily_hour_data[date_key][hour]['unauth_peak']:
                    daily_hour_data[date_key][hour]['unauth_peak'] = unauth_second_counts[second_str]

            elif "Authorized" in e.status:
                daily_hour_data[date_key][hour]['auth_mins'].add(minute_str)

                if p_name != 'Unknown':
                    daily_hour_data[date_key][hour]['auth_names'].add(p_name)
                else:
                    daily_hour_data[date_key][hour]['has_unknown_auth'] = True

        num_days = len(daily_hour_data) if len(daily_hour_data) > 0 else 1

        predictions = {}
        for h in range(24):
            total_auth_head = 0
            total_unauth_head = 0
            total_auth_dur = 0
            total_unauth_dur = 0

            for d in daily_hour_data:
                hour_data = daily_hour_data[d][h]
                auth_headcount = len(hour_data['auth_names'])

                if auth_headcount == 0 and hour_data['has_unknown_auth']:
                    auth_headcount = 1

                total_auth_head += auth_headcount
                total_unauth_head += hour_data['unauth_peak']

                total_auth_dur += len(hour_data['auth_mins'])
                total_unauth_dur += len(hour_data['unauth_mins'])

            predictions[h] = {
                'auth': round(total_auth_head / num_days),
                'unauth': round(total_unauth_head / num_days),
                'auth_duration': round(total_auth_dur / num_days),
                'unauth_duration': round(total_unauth_dur / num_days)
            }

        return jsonify(status="success", predictions=predictions)
    except Exception as e:
        print(f"[ERROR] Failed to fetch predictions: {e}")
        return jsonify(status="error", message=str(e))

# --Quiet Hours--

@app.route('/get_quiet_hours')
@login_required
def get_quiet_hours():
    try:
        start = config.QUIET_HOURS_START
        end = config.QUIET_HOURS_END 
        if os.path.exists("settings.json"): # Pull saved quiet hour values from settings.json
            with open("settings.json", "r") as f:
                data = json.load(f)
                start = data.get("quiet_start", start)
                end = data.get("quiet_end", end)
        return jsonify(status="success", start=start, end=end)
    except Exception as e:
        return jsonify(status="error", message=str(e))

@app.route('/update_quiet_hours', methods=['POST'])
@login_required
@admin_required
def update_quiet_hours():
    data = request.json
    try:
        new_start = int(data.get('start'))
        new_end = int(data.get('end'))

        # safely read/write by pulling existing settings to prevent overwrites
        settings = {}
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)

        settings["quiet_start"] = new_start
        settings["quiet_end"] = new_end

        with open("settings.json", "w") as f: # update quiet hour values
            json.dump(settings, f, indent=4)

        log_user_action("Updated Quiet Hours", f"Set to {new_start}:00 - {new_end}:00") # <--- NEW AUDIT HOOK
        return jsonify(status="success", message="Quiet hours updated!")
    except Exception as e:
        return jsonify(status="error", message=str(e))

# --Data Retention--

@app.route('/get_retention')
@login_required
def get_retention():
    try:
        days = 90
        if os.path.exists("settings.json"): # data retention threshold saved on settings.json
            with open("settings.json", "r") as f:
                data = json.load(f)
                days = data.get("log_retention_days", 90)
        return jsonify(status="success", days=days)
    except Exception as e:
        return jsonify(status="error", message=str(e))

@app.route('/update_retention', methods=['POST'])
@login_required
@admin_required
def update_retention():
    data = request.json
    try:
        new_days = int(data.get('days'))

        # safely read/write by loading prexisting settings first
        settings = {}
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)

        settings["log_retention_days"] = new_days

        with open("settings.json", "w") as f:
            json.dump(settings, f, indent=4)

        log_user_action("Updated Retention Policy", f"Set database auto-clean to {new_days} days.")
        return jsonify(status="success", message="Retention policy updated!")
    except Exception as e:
        return jsonify(status="error", message=str(e))

# --Privacy Control Routes--

@app.route('/get_anonymize_mode')
@login_required
def get_anonymize_mode():
    try:
        enabled = False
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                data = json.load(f)
                enabled = data.get("anonymized_mode", False) # Defualt toggle anonymized mode off
        return jsonify(status="success", enabled=enabled)
    except Exception as e:
        return jsonify(status="error", message=str(e))


@app.route('/update_anonymize_mode', methods=['POST'])
@login_required
@admin_required
def update_anonymize_mode():
    data = request.json
    try:
        enabled = bool(data.get('enabled'))

        # safely read/write by loading prexisting settings first
        settings = {}
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)

        settings["anonymized_mode"] = enabled

        with open("settings.json", "w") as f:
            json.dump(settings, f, indent=4)

        status_text = "Enabled" if enabled else "Disabled"
        log_user_action("Updated Privacy Settings", f"{status_text} Anonymized Mode.")
        return jsonify(status="success", message=f"Anonymized mode {status_text.lower()}!")
    except Exception as e:
        return jsonify(status="error", message=str(e))

@app.route('/get_privacy_zone')
@login_required
def get_privacy_zone():
    """Fetches the current privacy zone coordinates for the dashboard."""
    try:
        # Default fallback values if none exist yet
        pz_data = {"enabled": False, "x1": 100, "y1": 50, "x2": 400, "y2": 300} # Rectangular blur zones hence 4 coordinates

        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)
                pz_data = settings.get("privacy_zone", pz_data)

        return jsonify(status="success", data=pz_data)
    except Exception as e:
        return jsonify(status="error", message=str(e))


@app.route('/update_privacy_zone', methods=['POST'])
@login_required
@admin_required
def update_privacy_zone():
    """Saves new privacy zone coordinates from the dashboard to settings.json."""
    data = request.json
    try:
        # safely read/write by loading prexisting settings first
        settings = {}
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)

        # Update just the privacy_zone dictionary
        settings["privacy_zone"] = {
            "enabled": bool(data.get("enabled", False)),
            "x1": int(data.get("x1", 0)),
            "y1": int(data.get("y1", 0)),
            "x2": int(data.get("x2", 0)),
            "y2": int(data.get("y2", 0))
        }

        
        with open("settings.json", "w") as f:
            json.dump(settings, f, indent=4)

        
        status_text = "Enabled" if settings["privacy_zone"]["enabled"] else "Disabled"
        log_user_action("Updated Privacy Zone", f"{status_text} the physical camera blur mask.") # Add to Audit Log table

        return jsonify(status="success", message="Privacy Zone updated successfully!")
    except Exception as e:
        return jsonify(status="error", message=str(e))


# --User Management Routes--

@app.route('/authorized_users')
@login_required
def get_authorized_users():
    try:
        names = config.AUTHORIZED_NAMES
        return jsonify(status="success", count=len(names), names=names)
    except Exception as e:
        return jsonify(status="error", message=str(e), count=0, names=[])

@app.route('/remove_user', methods=['POST'])
@login_required
@admin_required
def remove_user():
    try:
        data = request.json
        name_to_remove = data.get('name')
        if not name_to_remove:
             return jsonify({"status": "error", "message": "No name provided"}), 400

        if name_to_remove in config.AUTHORIZED_NAMES:
            config.AUTHORIZED_NAMES.remove(name_to_remove)
            try:
                with open('config.py', 'r') as f:
                    content = f.read()
                new_list_code = f"AUTHORIZED_NAMES = {json.dumps(config.AUTHORIZED_NAMES, indent=4)}"
                content = re.sub(r'AUTHORIZED_NAMES\s*=\s*\[.*?\]', new_list_code, content, flags=re.DOTALL)
                with open('config.py', 'w') as f:
                    f.write(content)

            except Exception as file_error:
                return jsonify({"status": "error", "message": f"Failed to save config file: {str(file_error)}"}), 500
            return jsonify({"status": "success", "message": f"User {name_to_remove} removed."})
        else:
            return jsonify({"status": "error", "message": "User not found"}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --Registering New Users Routes--

@app.route('/register_user', methods=['POST'])
@login_required
@admin_required
def register_user():
    try:
        name = request.form.get('name')
        if not name:
            return jsonify({"status": "error", "message": "Name is required"}), 400

        if 'images' not in request.files:
            return jsonify({"status": "error", "message": "No images uploaded"}), 400

        files = request.files.getlist('images')
        if not files or files[0].filename == '':
            return jsonify({"status": "error", "message": "No selected file"}), 400

        user_folder = os.path.join(DATASET_DIR, name)
        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        for i, file in enumerate(files):
            if file:
                filename = file.filename
                ext = os.path.splitext(filename)[1].lower()

                if ext == '.jpeg':
                    final_filename = f"{name}_{int(time.time()*1000)}_{i}.jpeg"
                    final_path = os.path.join(user_folder, final_filename)
                    file.save(final_path)
                elif ext == '.jpg':
                    final_filename = f"{name}_{int(time.time()*1000)}_{i}.jpg"
                    final_path = os.path.join(user_folder, final_filename)
                    file.save(final_path)
                else:
                    final_filename = f"{name}_{int(time.time()*1000)}_{i}.jpg"
                    final_path = os.path.join(user_folder, final_filename)
                    try:
                        file_bytes = np.frombuffer(file.read(), np.uint8)
                        img = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
                        if img is not None:
                            cv2.imwrite(final_path, img, [int(cv2.IMWRITE_JPEG_QUALITY), 95])
                    except Exception as conv_e:
                        print(f"Failed to convert {filename}: {conv_e}")
                        continue

        print("[INFO] Starting full re-training...")
        knownEncodings = []
        knownNames = []
        total_faces_processed = 0

        for root, dirs, files in os.walk(DATASET_DIR):
            for file in files:
                if file.lower().endswith(('.jpg', '.jpeg', '.png')):
                    imagePath = os.path.join(root, file)
                    person_name = os.path.basename(root)
                    image = cv2.imread(imagePath)
                    if image is None: continue
                    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
                    boxes = face_recognition.face_locations(rgb, model="hog")
                    encodings = face_recognition.face_encodings(rgb, boxes)
                    for encoding in encodings:
                        knownEncodings.append(encoding)
                        knownNames.append(person_name)
                        total_faces_processed += 1

        if total_faces_processed == 0:
            return jsonify({"status": "error", "message": "No faces found in dataset! Training aborted."}), 400

        print("[INFO] Serializing and encrypting encodings...")
        data = {"encodings": knownEncodings, "names": knownNames}

        
        pickled_data = pickle.dumps(data)

        # extract master encryption key
        key = get_encryption_key()

        if key:
            # secure data with Fernet
            fernet_padlock = Fernet(key)
            final_data_to_save = fernet_padlock.encrypt(pickled_data)
            print("[INFO] Biometric data safely encrypted.")
        else:
            
            final_data_to_save = pickled_data

        # Save only encrypted data to hard drive
        with open(ENCODINGS_FILE, "wb") as f:
            f.write(final_data_to_save) # final data to save is in encodings.pickle encoded with Fernet

        if name not in config.AUTHORIZED_NAMES:
            config.AUTHORIZED_NAMES.append(name)
            try:
                with open('config.py', 'r') as f:
                    content = f.read()
                new_list_code = f"AUTHORIZED_NAMES = {json.dumps(config.AUTHORIZED_NAMES, indent=4)}"
                content = re.sub(r'AUTHORIZED_NAMES\s*=\s*\[.*?\]', new_list_code, content, flags=re.DOTALL)
                with open('config.py', 'w') as f:
                    f.write(content)
            except Exception as config_error:
                return jsonify({"status": "error", "message": f"Failed to save config: {config_error}"}), 500

        log_user_action("Registered Identity", f"Added {name} to authorized list and retrained model.") 

        return jsonify({
            "status": "success",
            "message": f"Registered {name}. Re-trained model with {total_faces_processed} total faces."
        })

    except Exception as e:
        print(f"Error registering user: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

# --Automated email report generations--

now_str =  datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def generate_daily_report(target_date=None):
    """Generates the daily summary using actual SQLite database metrics."""
    with app.app_context():
        if target_date is None:
            
            target_date = datetime.now().date()

        print(f"\n[REPORT ENGINE] Crunching numbers for Daily Report: {target_date}...")

        # Establish time frame
        start_of_day = datetime(target_date.year, target_date.month, target_date.day, 0, 0, 0)
        end_of_day = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59)

        # Query detection events
        daily_events = DetectionEvent.query.filter(
            DetectionEvent.timestamp >= start_of_day,
            DetectionEvent.timestamp <= end_of_day
        ).all()

        total_events = len(daily_events)

        auth_names = set()
        unauth_events_count = 0

        for event in daily_events:
            if "Authorized" in event.status:
                if event.person_name and event.person_name != "Unknown":
                    # Avoid counting the same person multiple times
                    auth_names.add(event.person_name.replace('_', ' '))
            elif "Unauthorized" in event.status:
                unauth_events_count += 1

        # Queyr alert logs
        daily_alerts = AlertLog.query.filter(
            AlertLog.timestamp >= start_of_day,
            AlertLog.timestamp <= end_of_day
        ).all()

        total_alerts = len(daily_alerts)
        quiet_hour_triggers = 0
        emails_sent = 0

        for alert in daily_alerts:
            if alert.event_type == "Quiet Hours Breach":
                quiet_hour_triggers += 1
            if alert.method == "Email" and alert.status == "Success":
                emails_sent += 1

        # Compile data
        report_data = {
            "total_events": total_events,
            "auth_people_count": len(auth_names),
            "auth_names_list": list(auth_names),
            "unauth_events": unauth_events_count,
            "alerts_triggered": total_alerts,
            "quiet_hour_triggers": quiet_hour_triggers,
            "emails_sent": emails_sent
        }

        # Save to SQLite database
        new_report = SystemReport(
            coverage_date=target_date,
            report_type="Daily",
            content=json.dumps(report_data), # Save the real math to SQLite
            emailed_status=False
        )
        db.session.add(new_report)
        db.session.commit()
        print(f"[REPORT ENGINE] Daily Report for {target_date} saved to archive.\n")

        # Sending the actual email
        print("[REPORT ENGINE] Attempting to send actual daily email...")
        try:
            sender_email = os.getenv("EMAIL_ADDRESS")
            sender_password = os.getenv("EMAIL_PASSWORD")
            recipient_email = os.getenv("EMAIL_ADDRESS")

            
            msg = MIMEMultipart()
            msg['From'] = f"Security Dashboard <{sender_email}>"
            msg['To'] = recipient_email
            msg['Subject'] = f"Security System: Daily Report ({target_date})"

            # Use queried data to construct email
            auth_names_str = ", ".join(report_data['auth_names_list']) if report_data['auth_names_list'] else "None"


            html_body = f"""
            <html>
              <body style="font-family: 'Helvetica Neue', Arial, sans-serif; color: #334155; background-color: #f8fafc; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">

                    <h2 style="color: #4f46e5; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; font-size: 24px;">
                        IoT Security System
                    </h2>
                    <p style="font-size: 14px; color: #64748b; margin-top: -5px;">Daily Operations Summary for <strong>{target_date}</strong></p>

                    <div style="background-color: #f1f5f9; padding: 20px; border-radius: 8px; margin: 25px 0; text-align: center;">
                        <p style="margin: 0; font-size: 14px; color: #475569; text-transform: uppercase; letter-spacing: 1px; font-weight: bold;">Total Camera Detections</p>
                        <p style="margin: 10px 0 0 0; font-size: 36px; color: #4f46e5; font-weight: bold;">{report_data['total_events']}</p>
                    </div>

                    <h3 style="color: #0f172a; font-size: 16px; margin-bottom: 15px;">Personnel Breakdown</h3>
                    <div style="border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 25px;">
                        <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin: 0; padding: 0;">
                            <tr>
                                <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; background-color: #ffffff; text-align: left;">
                                    <strong style="display: block; color: #334155; margin-bottom: 4px;">Distinct Authorized People</strong>
                                    <span style="font-size: 12px; color: #64748b;">Detected: {auth_names_str}</span>
                                </td>
                                <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; background-color: #ffffff; text-align: right; vertical-align: middle;">
                                    <strong style="color: #10b981; font-size: 22px;">{report_data['auth_people_count']}</strong>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 15px; background-color: #fff1f2; text-align: left;">
                                    <strong style="color: #9f1239;">Unauthorized Snapshots</strong>
                                </td>
                                <td style="padding: 15px; background-color: #fff1f2; text-align: right; vertical-align: middle;">
                                    <strong style="color: #e11d48; font-size: 22px;">{report_data['unauth_events']}</strong>
                                </td>
                            </tr>
                        </table>
                    </div>

                    <h3 style="color: #0f172a; font-size: 16px; margin-bottom: 15px;">Alerts & Security Actions</h3>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Total System Alerts Triggered</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold;">{report_data['alerts_triggered']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Quiet Hours Breaches</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #d97706;">{report_data['quiet_hour_triggers']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #475569;">Warning Emails Sent to Admin</td>
                            <td style="padding: 10px 0; text-align: right; font-weight: bold;">{report_data['emails_sent']}</td>
                        </tr>
                    </table>

                    <div style="margin-top: 35px; border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center;">
                        <p style="font-size: 12px; color: #94a3b8; margin: 0;">Automated daily report generated by Raspberry Pi and SQLite database.</p>
                        <p style="font-size: 12px; color: #94a3b8; margin: 5px 0 0 0;">Check the dashboard for live footage and predictive statistics.</p>
                    </div>
                </div>
              </body>
            </html>
            """

            
            msg.attach(MIMEText(html_body, 'html'))

            # Connect to Gmail and send
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            # Update the database to reflect successful delivery
            new_report.emailed_status = True
            db.session.commit()

            print(f"[REPORT ENGINE] Actual email sent successfully to {recipient_email}!")

        except AttributeError:
            print("[REPORT ENGINE ERROR] Could not find EMAIL_ADDRESS or EMAIL_PASSWORD in config.py!")
        except Exception as e:
            print(f"[REPORT ENGINE ERROR] Failed to send email: {e}")

def generate_weekly_report(target_date=None):
    """Generates a week over week comparison report."""
    with app.app_context():
        if target_date is None:
            # Default to today if scheduled normally
            target_date = datetime.now().date()

        print(f"\n[REPORT ENGINE] Crunching numbers for Weekly Report (Target: {target_date})...")

        # Set the timeframes
        current_end = datetime(target_date.year, target_date.month, target_date.day, 23, 59, 59)
        current_start = (current_end - timedelta(days=6)).replace(hour=0, minute=0, second=0)

        # 7 days before current week
        prev_end = current_start - timedelta(seconds=1)
        prev_start = (prev_end - timedelta(days=6)).replace(hour=0, minute=0, second=0)

        # Database queries
        curr_events = DetectionEvent.query.filter(DetectionEvent.timestamp >= current_start, DetectionEvent.timestamp <= current_end).all()
        prev_events = DetectionEvent.query.filter(DetectionEvent.timestamp >= prev_start, DetectionEvent.timestamp <= prev_end).all()

        curr_alerts = AlertLog.query.filter(AlertLog.timestamp >= current_start, AlertLog.timestamp <= current_end).all()
        prev_alerts = AlertLog.query.filter(AlertLog.timestamp >= prev_start, AlertLog.timestamp <= prev_end).all()

        # Calculations
        curr_total = len(curr_events)
        prev_total = len(prev_events)

        curr_unauth = sum(1 for e in curr_events if "Unauthorized" in e.status)
        prev_unauth = sum(1 for e in prev_events if "Unauthorized" in e.status)

        curr_quiet = sum(1 for a in curr_alerts if a.event_type == "Quiet Hours Breach")
        prev_quiet = sum(1 for a in prev_alerts if a.event_type == "Quiet Hours Breach")

        # Personalized insights by counting based on specific individual
        name_counts = {}
        for e in curr_events:
            if "Authorized" in e.status and e.person_name and e.person_name != "Unknown":
                clean_name = e.person_name.replace('_', ' ')
                name_counts[clean_name] = name_counts.get(clean_name, 0) + 1

        # Most commonly viewed calculations
        if name_counts:
            best_name = max(name_counts, key=name_counts.get) # Finds the name with the highest frequency
            most_viewed = f"{best_name} ({name_counts[best_name]} times)"
        else:
            most_viewed = "None detected"

        # Calculate most dormat user
        all_auth_names = [n.replace('_', ' ') for n in config.AUTHORIZED_NAMES]
        if all_auth_names:
            # Map every authorized user to their count (Default to 0 if they weren't seen at all)
            auth_counts = {name: name_counts.get(name, 0) for name in all_auth_names}
            min_count = min(auth_counts.values()) 

            # Find everyone who shares that lowest number
            dormant_users = [name for name, count in auth_counts.items() if count == min_count]

            
            dormant_str = ", ".join(dormant_users[:3])
            if len(dormant_users) > 3:
                dormant_str += f" (+{len(dormant_users)-3} more)"

            most_dormant = f"{dormant_str} ({min_count} times)"
        else:
            most_dormant = "No users configured"

        # Temporal Analysis Math

        # Busiest day of the week
        days_of_week = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        day_counts = {day: 0 for day in days_of_week}
        for e in curr_events:
            # e.timestamp.weekday() returns a number 0-6 where Monday is 0, Sunday is 6
            day_name = days_of_week[e.timestamp.weekday()]
            day_counts[day_name] += 1

        if sum(day_counts.values()) > 0:
            best_day = max(day_counts, key=day_counts.get)
            busiest_day_str = f"{best_day} ({day_counts[best_day]} events)"
        else:
            busiest_day_str = "No traffic"

        # Most congested hour
        hour_counts = {h: 0 for h in range(24)}
        for e in curr_events:
            hour_counts[e.timestamp.hour] += 1

        # Helper function to reformat hours
        def format_hour(h):
            am_pm = "AM" if h < 12 else "PM"
            display_h = h if h <= 12 else h - 12
            if display_h == 0: display_h = 12
            return f"{display_h}:00 {am_pm}"

        if sum(hour_counts.values()) > 0:
            best_hour = max(hour_counts, key=hour_counts.get)
            congested_hour_str = f"{format_hour(best_hour)} ({hour_counts[best_hour]} events)"
        else:
            congested_hour_str = "No traffic"

        # Most email alerts hour
        alert_hour_counts = {h: 0 for h in range(24)}
        alerts_sent = 0
        for a in curr_alerts:
            # Only count actual successful emails, not quiet hour logs
            if a.method == "Email" and a.status == "Success":
                alert_hour_counts[a.timestamp.hour] += 1
                alerts_sent += 1

        if alerts_sent > 0:
            worst_alert_hour = max(alert_hour_counts, key=alert_hour_counts.get)
            alert_hour_str = f"{format_hour(worst_alert_hour)} ({alert_hour_counts[worst_alert_hour]} emails)"
        else:
            alert_hour_str = "No alerts sent"

        # Percentage trend calculator
        def calc_trend(curr, prev, lower_is_better=False):
            if prev == 0:
                if curr == 0: return "<span style='color: #64748b;'>0%</span>"
                return f"<span style='color: {'#e11d48' if lower_is_better else '#3b82f6'};'>Up from 0</span>"

            change = ((curr - prev) / prev) * 100
            sign = "+" if change > 0 else ""

            if change == 0: color = "#64748b" 
            elif change > 0: color = "#e11d48" if lower_is_better else "#3b82f6" # Red if bad, Blue if neutral
            else: color = "#10b981" if lower_is_better else "#3b82f6" # Green if bad things went down

            return f"<span style='color: {color}; font-weight: bold;'>{sign}{change:.1f}%</span>"

        # Compile data and save to SQLite database
        report_data = {
            "dates": f"{current_start.strftime('%b %d')} - {current_end.strftime('%b %d')}",
            "curr_total": curr_total, "prev_total": prev_total,
            "curr_unauth": curr_unauth, "prev_unauth": prev_unauth,
            "curr_quiet": curr_quiet, "prev_quiet": prev_quiet,
            "most_viewed": most_viewed,
            "most_dormant": most_dormant,
            "busiest_day": busiest_day_str,        
            "congested_hour": congested_hour_str, 
            "alert_hour": alert_hour_str          
        }

        new_report = SystemReport(
            coverage_date=target_date,
            report_type="Weekly",
            content=json.dumps(report_data),
            emailed_status=False
        )
        db.session.add(new_report)
        db.session.commit()

        # Send HTML email
        try:
            sender_email = os.getenv("EMAIL_ADDRESS")
            sender_password = os.getenv("EMAIL_PASSWORD")
            recipient_email = os.getenv("EMAIL_ADDRESS")

            msg = MIMEMultipart()
            msg['From'] = f"Security Dashboard <{sender_email}>"
            msg['To'] = recipient_email
            msg['Subject'] = f"Security System: Weekly Trend Analysis ({report_data['dates']})"

            html_body = f"""
            <html>
              <body style="font-family: 'Helvetica Neue', Arial, sans-serif; color: #334155; background-color: #f8fafc; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">

                    <h2 style="color: #4f46e5; margin-top: 0; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; font-size: 24px;">
                        Weekly Security Analysis
                    </h2>
                    <p style="font-size: 14px; color: #64748b; margin-top: -5px;">Comparing <strong>{report_data['dates']}</strong> to the previous week.</p>

                    <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin-top: 25px; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden;">
                        <tr style="background-color: #f1f5f9; text-transform: uppercase; font-size: 11px; letter-spacing: 1px; color: #475569;">
                            <th style="padding: 12px 15px; text-align: left;">Metric</th>
                            <th style="padding: 12px 15px; text-align: center;">This Week</th>
                            <th style="padding: 12px 15px; text-align: center;">Last Week</th>
                            <th style="padding: 12px 15px; text-align: right;">Trend</th>
                        </tr>

                        <tr>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-weight: bold;">Total Camera Traffic</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: center; font-size: 18px;">{curr_total}</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: center; color: #94a3b8;;">{prev_total}</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: right;">{calc_trend(curr_total, prev_total, lower_is_better=False)}</td>
                        </tr>

                        <tr style="background-color: #fff1f2;">
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; font-weight: bold; color: #9f1239;">Unauthorized Events</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: center; font-size: 18px; color: #e11d48; font-weight: bold;">{curr_unauth}</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: center; color: #f43f5e; opacity: 0.7;">{prev_unauth}</td>
                            <td style="padding: 15px; border-bottom: 1px solid #e2e8f0; text-align: right;">{calc_trend(curr_unauth, prev_unauth, lower_is_better=True)}</td>
                        </tr>

                        <tr>
                            <td style="padding: 15px; font-weight: bold; color: #b45309;">Quiet Hour Breaches</td>
                            <td style="padding: 15px; text-align: center; font-size: 18px; color: #d97706; font-weight: bold;">{curr_quiet}</td>
                            <td style="padding: 15px; text-align: center; color: #f59e0b; opacity: 0.7;">{prev_quiet}</td>
                            <td style="padding: 15px; text-align: right;">{calc_trend(curr_quiet, prev_quiet, lower_is_better=True)}</td>
                        </tr>
                    </table>

                    <div style="margin-top: 28px; border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: center;">
                    </div>

                     <h3 style="color: #0f172a; font-size: 16px; margin-bottom: 15px;">Personalized Insights</h3>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Most Commonly Viewed Visitor</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #10b981;">{report_data['most_viewed']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Most Dormant Authorized User</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #d97706;">{report_data['most_dormant']}</td>
                        </tr>
                    </table>

                     <h3 style="color: #0f172a; font-size: 16px; margin-bottom: 15px;">Temporal Analysis</h3>
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Busiest User Traffic Day</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #3b82f6;">{report_data['busiest_day']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Most Congested Hour</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #8b5cf6;">{report_data['congested_hour']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; color: #475569;">Most Email Alerts Hour</td>
                            <td style="padding: 10px 0; border-bottom: 1px solid #f1f5f9; text-align: right; font-weight: bold; color: #e11d48;">{report_data['alert_hour']}</td>
                        </tr>

                        <tr>
                            <td colspan="2" style="padding-top: 10px;">
                                <p style="font-size: 12px; text-align: center; color: #94a3b8; margin: 0;"> Recommended to review the images attached in emails sent during extended unauthorized residence times and quiet hour breaches, as these provide important context for critical security events</p>
                            </td>
                        </tr>

                    </table>

                    <div>
                        <p style="font-size: 12px; text-align: center; color: #94a3b8; margin-top: 20px;">Automated weekly report.</p>
                    </div>
                </div>
              </body>
            </html>
            """

            msg.attach(MIMEText(html_body, 'html'))

            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            new_report.emailed_status = True
            db.session.commit()
            print(f"[REPORT ENGINE] Weekly email sent successfully!")

        except Exception as e:
            print(f"[REPORT ENGINE ERROR] Failed to send weekly email: {e}")

def generate_monthly_report(target_date=None):
    """Generates the monthly executive report"""
    with app.app_context():
        # Set the timeframes
        if target_date is None:
            # Monthly reports run on the 1st, goal is to analyze the previous month
            target_date = (datetime.now() - timedelta(days=1)).date()

        month_name = target_date.strftime('%B %Y')
        print(f"\n[REPORT ENGINE] Compiling Executive Audit for {month_name}...")

        # Get the absolute first and last second of that specific month
        month_start = datetime(target_date.year, target_date.month, 1, 0, 0, 0)
        last_day = calendar.monthrange(target_date.year, target_date.month)[1]
        month_end = datetime(target_date.year, target_date.month, last_day, 23, 59, 59)

        # Query the database
        month_events = DetectionEvent.query.filter(
            DetectionEvent.timestamp >= month_start,
            DetectionEvent.timestamp <= month_end
        ).all()

        # We query the SystemReports table to audit the system's uptime
        month_reports = SystemReport.query.filter(
            SystemReport.coverage_date >= month_start.date(),
            SystemReport.coverage_date <= month_end.date()
        ).all()

        # Security ratio math
        total_events = len(month_events)
        auth_count = sum(1 for e in month_events if "Authorized" in e.status)
        unauth_count = sum(1 for e in month_events if "Unauthorized" in e.status)

        auth_pct = (auth_count / total_events * 100) if total_events > 0 else 0
        unauth_pct = (unauth_count / total_events * 100) if total_events > 0 else 0

        # Calculate the busiest week
        week_counts = {"Week 1 (1st-7th)": 0, "Week 2 (8th-14th)": 0, "Week 3 (15th-21st)": 0, "Week 4 (22nd+)": 0}
        for e in month_events:
            d = e.timestamp.day
            if d <= 7: week_counts["Week 1 (1st-7th)"] += 1
            elif d <= 14: week_counts["Week 2 (8th-14th)"] += 1
            elif d <= 21: week_counts["Week 3 (15th-21st)"] += 1
            else: week_counts["Week 4 (22nd+)"] += 1

        if total_events > 0:
            busiest_week = max(week_counts, key=week_counts.get)
            busiest_week_str = f"{busiest_week} ({week_counts[busiest_week]} events)"
        else:
            busiest_week_str = "No recorded traffic"

        # Revocation list math
        all_auth_names = [n.replace('_', ' ') for n in config.AUTHORIZED_NAMES]
        seen_names = set()
        for e in month_events:
            if "Authorized" in e.status and e.person_name and e.person_name != "Unknown":
                seen_names.add(e.person_name.replace('_', ' '))

        # Find anyone in the config file who wasn't seen a single time
        dormant_users = [name for name in all_auth_names if name not in seen_names]
        revocation_str = ", ".join(dormant_users) if dormant_users else "None. All users active."

        # Infrastucture and uptime math
        catch_ups = sum(1 for r in month_reports if r.timestamp.date() > r.coverage_date)
        if catch_ups == 0:
            health_status = f"100% Scheduled Uptime (0 offline recoveries needed)"
            health_color = "#10b981" # Green
        else:
            health_status = f"Interrupted ({catch_ups} offline recovery runs triggered)"
            health_color = "#f59e0b" # Orange

        # Save to database
        report_data = {
            "month_name": month_name,
            "total_events": total_events,
            "auth_pct": round(auth_pct, 1),
            "unauth_pct": round(unauth_pct, 1),
            "busiest_week": busiest_week_str,
            "revocation_list": revocation_str,
            "catch_ups": catch_ups,
            "health_status": health_status
        }

        new_report = SystemReport(
            coverage_date=target_date,
            report_type="Monthly",
            content=json.dumps(report_data),
            emailed_status=False
        )
        db.session.add(new_report)
        db.session.commit()

        # Send HTML rendered email
        try:
            sender_email = os.getenv("EMAIL_ADDRESS")
            sender_password = os.getenv("EMAIL_PASSWORD")
            recipient_email = os.getenv("EMAIL_ADDRESS")

            msg = MIMEMultipart()
            msg['From'] = f"Security Administration <{sender_email}>"
            msg['To'] = recipient_email
            msg['Subject'] = f"MONTHLY Security Audit ({month_name})"

            html_body = f"""
            <html>
              <body style="font-family: 'Helvetica Neue', Arial, sans-serif; color: #1e293b; background-color: #f1f5f9; padding: 20px;">
                <div style="max-width: 650px; margin: 0 auto; background: white; padding: 35px; border-top: 5px solid #0f172a; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);">

                    <h2 style="color: #0f172a; margin-top: 0; font-size: 26px; letter-spacing: -0.5px;">
                        Monthly Executive Overview
                    </h2>
                    <p style="font-size: 13px; color: #64748b; margin-top: -10px; text-transform: uppercase; letter-spacing: 1px;">Period: {month_name}</p>

                    <div style="margin-top: 30px; border-left: 3px solid #3b82f6; padding-left: 15px;">
                        <h3 style="color: #0f172a; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Security Authorization Ratio</h3>
                        <p style="color: #475569; font-size: 14px; margin-top: 0;">Of the <b> {total_events} </b> total events logged this month:</p>

                        <div style="display: flex; gap: 20px; margin-top: 15px;">
                            <div style="flex: 1; background-color: #f8fafc; padding: 15px; border: 1px solid #e2e8f0;">
                                <span style="display: block; font-size: 11px; color: #64748b; text-transform: uppercase;">Authorized</span>
                                <span style="font-size: 24px; font-weight: bold; color: #10b981;">{report_data['auth_pct']}%</span>
                            </div>
                            <div style="flex: 1; background-color: #f8fafc; padding: 15px; border: 1px solid #e2e8f0;">
                                <span style="display: block; font-size: 11px; color: #64748b; text-transform: uppercase;">Unauthorized</span>
                                <span style="font-size: 24px; font-weight: bold; color: #e11d48;">{report_data['unauth_pct']}%</span>
                            </div>
                        </div>
                    </div>

                    <div style="margin-top: 35px; border-left: 3px solid #8b5cf6; padding-left: 15px;">
                        <h3 style="color: #0f172a; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Weekly Traffic Statistics</h3>
                        <p style="color: #475569; font-size: 14px; margin-top: 0;">
                            <strong>Busiest Weekly Period:</strong> <span style="color: #334155;">{report_data['busiest_week']}</span>
                        </p>
                    </div>

                    <div style="margin-top: 35px; border-left: 3px solid #e11d48; padding-left: 15px;">
                        <h3 style="color: #0f172a; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">30-Day Access Report</h3>
                        <p style="color: #475569; font-size: 14px; margin-top: 0;">The following authorized personnel were <strong> not detected once </strong> during the last 30 days. Reconsider their authorization status via the dashboard:</p>
                        <div style="margin-top: 10px; padding: 12px; background-color: #fff1f2; border: 1px solid #fecdd3; color: #9f1239; font-weight: bold; font-size: 14px;">
                            {report_data['revocation_list']}
                        </div>
                    </div>

                    <div style="margin-top: 35px; border-left: 3px solid #0f172a; padding-left: 15px;">
                        <h3 style="color: #0f172a; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px;">Infrastructure Health </h3>
                        <p style="color: #475569; font-size: 14px; margin-top: 0;">
                            <strong>Raspberry Pi Status:</strong> <span style="color: {health_color}; font-weight: bold;">{report_data['health_status']}</span>
                        </p>
                        <p style="color: #64748b; font-size: 12px; margin-top: 5px; font-style: italic;">
                            *Offline recovery runs indicate that the Pi was turned off during a scheduled report window, triggering the catch-up function upon reboot.
                        </p>
                    </div>
                    
                    <div style="margin-top: 40px; border-top: 1px solid #e2e8f0; padding-top: 20px; text-align: left;">
                        <p style="font-size: 11px; color: #94a3b8; margin: 0; text-transform: uppercase; letter-spacing: 1px;">End of Official Record</p>
                    </div>
                </div>
              </body>
            </html>
            """
            
            msg.attach(MIMEText(html_body, 'html'))

            # Connect to Gmail and send
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, recipient_email, msg.as_string())
            server.quit()

            new_report.emailed_status = True
            db.session.commit()
            print(f"[REPORT ENGINE] Monthly email sent successfully!")

        except Exception as e:
            print(f"[REPORT ENGINE ERROR] Failed to send monthly email: {e}")

def perform_data_retention_cleanup():
    """Automatically deletes old database records to save space and preserve privacy"""
    with app.app_context(): 
        print("\n[JANITOR] Starting automated data retention cleanup...")

        # Grab the retention days value from settings.json (default to 90 days)
        log_retention_days = 90
        if os.path.exists("settings.json"):
            try:
                with open("settings.json", "r") as f:
                    data = json.load(f)
                    # Use 90 as a safe default if the setting isn't in the file yet
                    log_retention_days = int(data.get("log_retention_days", 90))
            except Exception as e:
                print(f"[JANITOR ERROR] Failed to read settings: {e}")

        # Use timedelta to calculate the exact cutoff date
        cutoff_datetime = datetime.now() - timedelta(days=log_retention_days)
        print(f"[JANITOR] Deleting records older than {log_retention_days} days (Before {cutoff_datetime.strftime('%Y-%m-%d')})...")

        try:
            # 3. Clean up DetectionEvent and SystemLog table based on the cutoff date
            deleted_events = db.session.query(DetectionEvent).filter(DetectionEvent.timestamp < cutoff_datetime).delete()
            deleted_syslogs = db.session.query(SystemLog).filter(SystemLog.timestamp < cutoff_datetime).delete()

            db.session.commit()

            print(f"[JANITOR SUCCESS] Deleted {deleted_events} Events and {deleted_syslogs} System Logs.")

            # Log this cleanup to SystemLog
            log_system_event(
                level="INFO",
                event_type="Retention",
                message="Data Deleted",
                details=f"Auto-cleaned {deleted_events} Events and {deleted_syslogs} System Logs."
            )

        except Exception as e:
            db.session.rollback() 
            print(f"[JANITOR ERROR] Database cleanup failed: {e}")


def check_missed_reports():
    """Runs when the server starts to see if it was turned off during a scheduled report"""
    with app.app_context():
        # Daily recovery
        yesterday = (datetime.now() - timedelta(days=1)).date()

        # Check if email was sent yesterday
        missed_daily = SystemReport.query.filter_by(report_type="Daily", coverage_date=yesterday).first()

        if not missed_daily:
            print(f"[RECOVERY] Missed Daily Report detected for {yesterday}. Generating now...")
            generate_daily_report(target_date=yesterday)
        else:
            print(f"[RECOVERY] Daily Report for {yesterday} is up to date.")

        # Weekly recovery
        today = datetime.now().date()

        # Math to find the date of the most recent Sunday
        days_since_sunday = (today.weekday() + 1) % 7
        if days_since_sunday == 0: # If today is Sunday, set the check to past Sunday
            days_since_sunday = 7

        last_sunday = today - timedelta(days=days_since_sunday) #speical timedelta python class to determine today compared to a past date

        missed_weekly = SystemReport.query.filter_by(report_type="Weekly", coverage_date=last_sunday).first()

        if not missed_weekly:
            print(f"[RECOVERY] Missed Weekly Report detected for Sunday, {last_sunday}. Generating now...")
            generate_weekly_report(target_date=last_sunday)
        else:
            print(f"[RECOVERY] Weekly Report for {last_sunday} is up to date.\n")

# Database migration
def upgrade_db_schema():
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Add person)name
        try:
            cursor.execute("ALTER TABLE detection_event ADD COLUMN person_name VARCHAR(100) DEFAULT 'Unknown'")
            conn.commit()
            print("[INFO] Database Upgraded: Added 'person_name' tracking capability.")
        except sqlite3.OperationalError:
            pass 

        # Add duration_seconds
        try:
            cursor.execute("ALTER TABLE detection_event ADD COLUMN duration_seconds FLOAT DEFAULT 0.0")
            conn.commit()
            print("[INFO] Database Upgraded: Added 'duration_seconds' tracking capability.")
        except sqlite3.OperationalError:
            pass 

        conn.close()
    except Exception as e:
        print(f"[ERROR] Database upgrade failed: {e}")

upgrade_db_schema()

with app.app_context():
    db.create_all()
    print(f"\n[SUCCESS] Database initialized at: {db_path}\n")

# --APScheduler Start--
if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true": # Prevents Flask from running two schedules when auto-reloading
    scheduler = BackgroundScheduler()

    #[TESTING MODE] - Commented out so to prevent emailing every minute
    #scheduler.add_job(func=generate_daily_report, trigger="interval", minutes=1, id='test_email_job')

    # Schedule DAILY Report for 10:13 PM every day
    scheduler.add_job(func=generate_daily_report, trigger="cron", hour=22, minute=13)

    # Schedule WEEKLY Report for Sunday at 12:13 PM
    scheduler.add_job(func=generate_weekly_report, trigger="cron", day_of_week='sun', hour=12, minute=13)

    # Schedule MONTHLY Report for the 31st of every month at 10:51 PM
    scheduler.add_job(func=generate_monthly_report, trigger="cron", day='31', hour=22, minute=51)

    # Machine learning and calculations each day
    # Runs every single night at 11:22 PM to learn from the previous day's traffic
    scheduler.add_job(func=update_statistical_baselines, trigger="cron", hour=23, minute=22)

    # Data retention cleanup
    # Runs every day at 1:21 PM to clean up database
    scheduler.add_job(func=perform_data_retention_cleanup, trigger="cron", hour=13, minute=21)

    scheduler.start()
    print("[INFO] Background Report Scheduler Started.\n")

    # Run the offline recovery check
    check_missed_reports()

if __name__ == '__main__':
    print(f"Flask is running with Python: {sys.executable}")
    # Added ssl_context='adhoc' to enable local HTTPS ---
    socketio.run(app, debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')
