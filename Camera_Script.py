import face_recognition
import cv2
import numpy as np
from picamera2 import Picamera2
import time
import pickle
from gpiozero import LED
from datetime import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from dotenv import load_dotenv
import sys
import signal
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import sqlite3
import requests 
import importlib 
import urllib3
import socketserver 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variable secrets 
load_dotenv("secretcredentials.env")

# import settings
import config 

# Configure email
SENDER_EMAIL = os.getenv("EMAIL_ADDRESS")
SENDER_PASSWORD = os.getenv("EMAIL_PASSWORD")
RECEIVER_EMAIL = os.getenv("EMAIL_ADDRESS")

ALERT_COOLDOWN = 10.0
UNAUTH_THRESHOLD = 2.0 
LOG_FILE = "security_events.log"
RESET_PATIENCE = 2.0 

# Global variables for streaming
output_frame = None
lock = threading.Lock()

# Global variables for anomaly detection
baselines_data = None
current_tracking_hour = datetime.now().hour
hourly_event_count = 0
anomaly_alert_sent_this_hour = False

# Global variables for individual tracking
current_tracking_day = datetime.now().day
daily_user_counts = {}
daily_anomaly_alerts_sent = set()

# Live stopwatch tracker
active_visits = {} 
VISIT_BUFFER = 5.0 

# --Helper Functions--

def notify_dashboard(message, priority='INFO'): # Communicate with dashboard
    try:
        payload = {
            'timestamp': datetime.now().strftime("%H:%M:%S"),
            'message': message,
            'priority': priority
        }
        requests.post('https://localhost:5000/api/trigger_alert', json=payload, timeout=3.0, verify=False)
    except Exception as e:
        print(f"Dashboard notify failed: {e}")

def log_event(message, priority='INFO'): # Live event log to be displayed on dashboard
    timestamp = datetime.now().strftime("%H:%M:%S")
    entry = f"[{timestamp}] {message}"
    print(entry) 
    
    try:
        with open(LOG_FILE, "a") as f:
            f.write(entry + "\n")
    except:
        pass

    notify_dashboard(entry, priority)

def refresh_config():
    try:
        importlib.reload(config)
    except Exception as e:
        print(f"[ERROR] Could not reload config.py: {e}")

def load_baselines(): # Extract baseline data from baselines.json
    global baselines_data
    try:
        if os.path.exists("baselines.json"):
            with open("baselines.json", "r") as f:
                baselines_data = json.load(f)
            log_event("Statistical AI Baselines successfully loaded.", priority="INFO")
        else:
            log_event("baselines.json not found. Run Flask API to generate.", priority="INFO")
    except Exception as e:
        log_event(f"Error loading baselines: {e}", priority="ALERT")

# --DB Logging Functions--
def log_event_to_db(status, image_path=None, person_name="Unknown"):
    row_id = None
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, "surveillance.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        try:
            cursor.execute(
                "INSERT INTO detection_event (timestamp, status, image_path, person_name, duration_seconds) VALUES (?, ?, ?, ?, ?)",
                (now, status, image_path, person_name, 0.0)
            )
            row_id = cursor.lastrowid
        except sqlite3.OperationalError:
            try:
                cursor.execute(
                    "INSERT INTO detection_event (timestamp, status, image_path, person_name) VALUES (?, ?, ?, ?)",
                    (now, status, image_path, person_name)
                )
                row_id = cursor.lastrowid
            except sqlite3.OperationalError:
                cursor.execute(
                    "INSERT INTO detection_event (timestamp, status, image_path) VALUES (?, ?, ?)",
                    (now, status, image_path)
                )
                row_id = cursor.lastrowid
            
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Database write failed: {e}")
    
    return row_id

def update_event_duration(event_id, final_duration):
    if not event_id: return
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, "surveillance.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE detection_event SET duration_seconds = ? WHERE id = ?",
            (round(final_duration, 2), event_id)
        )
        
        conn.commit()
        conn.close()
    except Exception as e:
        pass 

def log_alert_to_db(method, recipient, event_type, status):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, "surveillance.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO alert_log (timestamp, method, recipient, event_type, status) VALUES (?, ?, ?, ?, ?)",
            (now, method, recipient, event_type, status)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Database write failed (Alert Log): {e}")

def log_system_event_to_db(level, event_type, message, details=None):
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(base_dir, "surveillance.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO system_log (timestamp, level, source, event_type, message, details) VALUES (?, ?, ?, ?, ?, ?)",
            (now, level, "Camera", event_type, message, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Database write failed (System Log): {e}")

def signal_handler(sig, frame):
    log_event("SYSTEM STOPPING...")
    log_system_event_to_db("INFO", "Shutdown", "Camera process stopping...")
    try:
        picam2.stop()
        output.off()
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

def is_quiet_hours(): # Checking for quiet hour parameters
    start = config.QUIET_HOURS_START
    end = config.QUIET_HOURS_END
    try:
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)
                start = int(settings.get("quiet_start", start))
                end = int(settings.get("quiet_end", end))
    except:
        pass 

    h = datetime.now().hour
    if start > end: return h >= start or h < end
    else: return start <= h < end

def is_anonymized_mode(): # Checking for anonymzed mode status
    try:
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)
                return settings.get("anonymized_mode", False)
    except:
        pass 
    return False

# Load privacy zone settings and apply them
def get_privacy_settings():
    """Reads the privacy zone coordinates from settings.json."""
    enabled = False
    coords = (0, 0, 0, 0)
    
    try:
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                settings = json.load(f)
                
            if "privacy_zone" in settings:
                pz = settings["privacy_zone"]
                enabled = pz.get("enabled", False)
                
                x1 = int(pz.get("x1", 0))
                y1 = int(pz.get("y1", 0))
                x2 = int(pz.get("x2", 0))
                y2 = int(pz.get("y2", 0))
                
                coords = (x1, y1, x2, y2)
    except Exception as e:
        pass 
        
    return enabled, coords

def get_encryption_key():
    biometric_key = os.getenv("BIOMETRIC_KEY")
    if biometric_key:
        return biometric_key.encode('utf-8') 
        
    print("[WARNING] BIOMETRIC_KEY not found! Camera cannot decrypt biometrics.")
    return None

# Streaming server class
class StreamingServer(socketserver.ThreadingMixIn, HTTPServer):
    allow_reuse_address = True
    daemon_threads = True

class MJPEGServer(BaseHTTPRequestHandler):
    def do_GET(self):
        global output_frame
        if self.path == '/stream.mjpg':
            self.send_response(200)
            self.send_header('Age', 0)
            self.send_header('Cache-Control', 'no-cache, private')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Content-Type', 'multipart/x-mixed-replace; boundary=FRAME')
            self.send_header('Access-Control-Allow-Origin', '*') 
            self.end_headers()
            try:
                while True:
                    with lock:
                        if output_frame is None:
                            continue
                        (flag, encodedImage) = cv2.imencode(".jpg", output_frame)
                    
                    if not flag: continue
                    
                    self.wfile.write(b'--FRAME\r\n')
                    self.send_header('Content-Type', 'image/jpeg')
                    self.send_header('Content-Length', len(encodedImage))
                    self.end_headers()
                    self.wfile.write(encodedImage)
                    self.wfile.write(b'\r\n')
                    time.sleep(0.05) 
            except Exception as e:
                pass
        else:
            self.send_error(404)

def start_stream_server():
    try:
        server = StreamingServer(('0.0.0.0', 5001), MJPEGServer)
        
        import ssl
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
        server.socket = context.wrap_socket(server.socket, server_side=True)

        print("[INFO] Multi-threaded SECURE Video Stream started on port 5001")
        server.serve_forever()
    except Exception as e:
        print(f"[ERROR] Could not start stream: {e}")

# --Email Alert Functions--
last_alert_time = 0

def send_email_alert(image_frame, duration): # Unauthorized person and quiet hour breach emails
    global last_alert_time
    if (time.time() - last_alert_time) < ALERT_COOLDOWN:
        return

    log_event(f"ALERT: Sending email (Duration: {duration:.1f}s)", priority="ALERT")
    
    q_start = config.QUIET_HOURS_START
    q_end = config.QUIET_HOURS_END
    try:
        if os.path.exists("settings.json"):
            with open("settings.json", "r") as f:
                s = json.load(f)
                q_start = s.get("quiet_start", q_start)
                q_end = s.get("quiet_end", q_end)
    except: pass

    event_type_log = "Unauthorized Person"
    if is_quiet_hours():
        event_type_log = "Quiet Hours Breach"

    try:
        _, encoded = cv2.imencode(".jpg", image_frame)
        msg = MIMEMultipart()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if is_quiet_hours():
            subj = f"URGENT: QUIET HOURS BREACH - {now_str}"
            body = (
                f"SECURITY WARNING: QUIET HOURS VIOLATION\n"
                f"=======================================\n"
                f"Time of Incident: {now_str}\n"
                f"Duration in View: {duration:.1f} seconds\n"
                f"Quiet Hours Schedule: {q_start}:00 - {q_end}:00\n"
                f"\n--- System Settings ---\n"
                f"Trigger Threshold: {UNAUTH_THRESHOLD} seconds\n"
                f"Alert Cooldown: {ALERT_COOLDOWN} seconds\n"
                f"=======================================\n\n"
                f"An unauthorized person was detected during restricted hours.\n"
                f"Please review the attached image immediately."
            )
        else:
            subj = f"Security Alert: Unauthorized Person - {now_str}"
            body = (
                f"SECURITY ALERT: UNAUTHORIZED ACTIVITY\n"
                f"---------------------------------------\n"
                f"Time: {now_str}\n"
                f"Duration in View: {duration:.1f} seconds\n"
                f"\n--- System Settings ---\n"
                f"Trigger Threshold: {UNAUTH_THRESHOLD} seconds\n"
                f"Alert Cooldown: {ALERT_COOLDOWN} seconds\n"
                f"---------------------------------------\n\n"
                f"An unknown individual has been detected by the security system.\n"
                f"See the attached capture for details."
            )

        msg['Subject'] = subj
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        msg.attach(MIMEText(body))
        msg.attach(MIMEImage(encoded.tobytes(), name="security_capture.jpg")) # Send jpg image of instance in the email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        
        log_event("EMAIL SENT SUCCESSFULLY", priority="INFO")
        log_alert_to_db("Email", RECEIVER_EMAIL, event_type_log, "Success")
        last_alert_time = time.time()
    except Exception as e:
        log_event(f"EMAIL FAILED: {e}", priority="ALERT")
        log_alert_to_db("Email", RECEIVER_EMAIL, event_type_log, "Failed")

def send_anomaly_alert(image_frame, current_count, threshold, hour_label): # Number of events detected exceeding typical threshold email
    log_event(f"STATISTICAL ANOMALY: {current_count} events exceeds normal threshold of {threshold}", priority="ALERT")
    
    try:
        _, encoded = cv2.imencode(".jpg", image_frame)
        msg = MIMEMultipart()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        msg['Subject'] = f"AI Anomaly Detected: Unusual Traffic Spike ({hour_label})"
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        body = (
            f"STATISTICAL ANOMALY ALERT: UNUSUAL TRAFFIC SPIKE\n"
            f"=============================================\n"
            f"Time of Detection: {now_str}\n"
            f"Current Hour: {hour_label}\n"
            f"\n--- Statistical Baseline Data ---\n"
            f"Events Detected This Hour: {current_count}\n"
            f"Anomaly Threshold (Mean + 2 StdDev): {threshold}\n"
            f"=============================================\n\n"
            f"The baseline engine has flagged the current traffic volume as a statistical anomaly "
            f"based on your historical household patterns. This indicates unusually high activity.\n\n"
            f"Latest capture attached for review."
        )

        msg.attach(MIMEText(body))
        msg.attach(MIMEImage(encoded.tobytes(), name="anomaly_capture.jpg"))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        
        log_event("ANOMALY EMAIL SENT SUCCESSFULLY", priority="INFO")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Statistical Anomaly", "Success")
    except Exception as e:
        log_event(f"ANOMALY EMAIL FAILED: {e}", priority="ALERT")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Statistical Anomaly", "Failed")


def send_individual_anomaly_alert(image_frame, person_name, current_count, threshold): # Individualized anomaly email
    log_event(f"BEHAVIORAL ANOMALY: {person_name} ({current_count} visits) exceeds daily limit of {threshold}", priority="ALERT")
    
    try:
        _, encoded = cv2.imencode(".jpg", image_frame)
        msg = MIMEMultipart()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        msg['Subject'] = f"Detection Frequency Alert: Unusual Activity for {person_name}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        body = (
            f"INDIVIDUAL FREQUENCY ALERT: BEHAVIORAL ANOMALY\n"
            f"=============================================\n"
            f"Time of Detection: {now_str}\n"
            f"Individual Flagged: {person_name}\n"
            f"\n--- Statistical Baseline Data ---\n"
            f"Total Detections Today: {current_count}\n"
            f"Daily Threshold (Mean + 2 StdDev): {threshold}\n"
            f"=============================================\n\n"
            f"{person_name} has been flagged for unusually high frequency today based on "
            f"their historical baseline.\n\n"
            f"Latest capture attached for review."
        )

        msg.attach(MIMEText(body))
        msg.attach(MIMEImage(encoded.tobytes(), name="anomaly_capture.jpg"))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        
        log_event("INDIVIDUAL ANOMALY EMAIL SENT", priority="INFO")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Behavioral Anomaly", "Success")
    except Exception as e:
        log_event(f"INDIVIDUAL ANOMALY EMAIL FAILED: {e}", priority="ALERT")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Behavioral Anomaly", "Failed")


def send_duration_anomaly_alert(image_frame, person_name, duration, threshold): # Individualized duration exceeds normal threshold
    log_event(f"DURATION ANOMALY: {person_name} ({duration:.1f}s) exceeded limit of {threshold}s", priority="ALERT")
    
    try:
        _, encoded = cv2.imencode(".jpg", image_frame)
        msg = MIMEMultipart()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        msg['Subject'] = f"Visit Duration Anomaly: Unusual Loitering by {person_name}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        body = (
            f"VISIT DURATION ALERT: BEHAVIORAL ANOMALY\n"
            f"=============================================\n"
            f"Time of Detection: {now_str}\n"
            f"Individual Flagged: {person_name}\n"
            f"\n--- Statistical Baseline Data ---\n"
            f"Current Visit Duration: {duration:.1f} seconds\n"
            f"Maximum Normal Threshold: {threshold:.1f} seconds\n"
            f"=============================================\n\n"
            f"{person_name} has been present in front of the camera for an unusually long period "
            f"compared to their historical visits. Recommended to look into {person_name}'s activity.\n\n"
            f"Latest capture attached for review."
        )

        msg.attach(MIMEText(body))
        msg.attach(MIMEImage(encoded.tobytes(), name="anomaly_capture.jpg"))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(SENDER_EMAIL, SENDER_PASSWORD)
            s.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        
        log_event("DURATION ANOMALY EMAIL SENT", priority="INFO")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Duration Anomaly", "Success")
    except Exception as e:
        log_event(f"DURATION ANOMALY EMAIL FAILED: {e}", priority="ALERT")
        log_alert_to_db("Email", RECEIVER_EMAIL, "Duration Anomaly", "Failed")


# Bounding box drawing function
def draw_results(frame, locations, names):
    for (top, right, bottom, left), name in zip(locations, names):
        top *= scaler
        right *= scaler
        bottom *= scaler
        left *= scaler
        
        is_authorized = False
        if name in config.AUTHORIZED_NAMES:
            is_authorized = True
        elif name.replace('_', ' ') in config.AUTHORIZED_NAMES:
            is_authorized = True
            name = name.replace('_', ' ') 
        
        if is_authorized:
            color = (0, 255, 0) # Green
        else:
            color = (0, 0, 255) # Red

        cv2.rectangle(frame, (left, top), (right, bottom), color, 3)
        cv2.rectangle(frame, (left -3, top - 35), (right+3, top), color, cv2.FILLED)
        font = cv2.FONT_HERSHEY_DUPLEX
        cv2.putText(frame, name, (left + 6, top - 6), font, 1.0, (255, 255, 255), 1)
        
        if is_authorized:
             cv2.putText(frame, "Authorized", (left + 6, bottom + 23), font, 0.6, color, 1)
        else:
             cv2.putText(frame, "Unauthorized", (left + 6, bottom + 23), font, 0.6, color, 1)

    if is_quiet_hours():
        cv2.putText(frame, "QUIET HOURS ACTIVE", (20, 60), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
    
    return frame

# Main Setup 
log_event("SYSTEM STARTING UP...")
log_system_event_to_db("INFO", "Startup", "Camera script initializing...")

# Load facial encodings
try:
    with open("encodings.pickle", "rb") as f:
        raw_file_data = f.read()
            
    key = get_encryption_key()
    
    if key: # Decrypting the encrypted encodings.pickle file
        try:
            fernet_padlock = Fernet(key)
            decrypted_bytes = fernet_padlock.decrypt(raw_file_data)
            data = pickle.loads(decrypted_bytes)
            log_event("Biometric data securely decrypted in RAM.", priority="INFO")
            
        except Exception as decrypt_error:
            print(f"[WARNING] Decryption failed (maybe it's an old unencrypted file?): {decrypt_error}")
            data = pickle.loads(raw_file_data)
    else:
        data = pickle.loads(raw_file_data)
        
    known_encodings = data["encodings"]
    known_names = data["names"]
    log_event(f"Loaded {len(known_names)} face encodings.")

except Exception as e:
    msg = f"CRITICAL ERROR: Could not load encodings: {e}"
    log_event(msg, priority="ALERT")
    log_system_event_to_db("ERROR", "Startup Failed", msg)
    sys.exit(1)

# Load statistical baselines
load_baselines()

picam2 = Picamera2()
config_cam = picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (1920, 1080)})
picam2.configure(config_cam)
picam2.start()

output = LED(17)
scaler = 4

# Timing variables
unauth_start = None
last_unauth_seen_time = 0 

# Performance tracking
perf_frame_count = 0
perf_start_time = time.time()
perf_last_log_time = time.time()
LOG_INTERVAL = 60 

# Config reload
last_config_check_time = 0
CONFIG_CHECK_INTERVAL = 5.0 

t = threading.Thread(target=start_stream_server, daemon=True)
t.start()

refresh_config()

log_event("CAMERA ACTIVE. MONITORING...")
log_system_event_to_db("INFO", "Running", "Camera loop started")

# Main camera inference loop
while True:
    try:
        loop_start = time.time() 
        now_time = time.time()

        if time.time() - last_config_check_time > CONFIG_CHECK_INTERVAL:
            refresh_config()
            last_config_check_time = time.time()

        now_hour = datetime.now().hour
        if now_hour != current_tracking_hour:
            current_tracking_hour = now_hour
            hourly_event_count = 0
            anomaly_alert_sent_this_hour = False
            load_baselines()

        now_day = datetime.now().day
        if now_day != current_tracking_day:
            current_tracking_day = now_day
            daily_user_counts = {}
            daily_anomaly_alerts_sent = set()

        frame = picam2.capture_array()
        frame = cv2.flip(frame, 0)
        
        # --Privacy zone mask--
        privacy_zone_enabled, privacy_zone_coords = get_privacy_settings()

        if privacy_zone_enabled:
            x1, y1, x2, y2 = privacy_zone_coords
            
            if x2 > x1 and y2 > y1: # Ensure valid user entered dimensions before masking 
                try:
                    rectangle = frame[y1:y2, x1:x2]
                    # Apply Gaussian blur to the selected region
                    blurred_rectangle = cv2.GaussianBlur(rectangle, (99, 99), 30)
                    # Stitch the blurred piece back into the main frame
                    frame[y1:y2, x1:x2] = blurred_rectangle
                except Exception as e:
                    print(f"Privacy Blur Error (check coordinates): {e}")
        
        
        small = cv2.resize(frame, (0, 0), fx=1/scaler, fy=1/scaler)
        rgb = cv2.cvtColor(small, cv2.COLOR_BGR2RGB)
        
        locs = face_recognition.face_locations(rgb)
        encs = face_recognition.face_encodings(rgb, locs)
        
        auth_found = False
        unauth_found = False
        names_found = []

        for enc in encs: # Facial recognition comparison to encodings, tolerance set to 45%
            matches = face_recognition.compare_faces(known_encodings, enc, tolerance=0.45)
            name = "Unknown"
            dists = face_recognition.face_distance(known_encodings, enc)
            
            if len(dists) > 0:
                best = np.argmin(dists)
                if matches[best]:
                    name = known_names[best]
            
            names_found.append(name)
            
            is_auth = False
            if name in config.AUTHORIZED_NAMES or name.replace('_', ' ') in config.AUTHORIZED_NAMES:
                is_auth = True

            if is_auth:
                auth_found = True
            else:
                unauth_found = True

        for name in names_found: # Checking for user authorization
            clean_name = name.replace('_', ' ')
            is_auth = (name in config.AUTHORIZED_NAMES or clean_name in config.AUTHORIZED_NAMES)
            if not is_auth:
                clean_name = "Unknown"
                
            if clean_name not in active_visits:
                status = "Authorized" if is_auth else "Unauthorized"
                
                db_name = name 
                if is_auth and is_anonymized_mode():
                    db_name = "Authorized User"
                
                db_id = log_event_to_db(status, person_name=db_name) 
                
                active_visits[clean_name] = { 
                    'start': now_time,
                    'last_seen': now_time,
                    'db_id': db_id,
                    'alert_sent': False,
                    'raw_name': name
                }
                
                log_event(f"Detected: {db_name} [{status.upper()}]")
                hourly_event_count += 1 
                
                if baselines_data and not anomaly_alert_sent_this_hour: # Anomaly checks
                    dt = datetime.now()
                    bucket = "Weekend" if dt.weekday() >= 5 else "Weekday"
                    am_pm = "AM" if dt.hour < 12 else "PM"
                    display_h = dt.hour if dt.hour <= 12 else dt.hour - 12
                    if display_h == 0: display_h = 12
                    hour_label = f"{display_h}:00 {am_pm}"
                    
                    hour_stats = baselines_data.get("statistical_baselines", {}).get(bucket, {}).get(hour_label)
                    if hour_stats:
                        threshold = hour_stats.get("anomaly_threshold_2SD", 9999)
                        if hourly_event_count > threshold:
                            send_anomaly_alert(frame, hourly_event_count, threshold, hour_label)
                            anomaly_alert_sent_this_hour = True
                
                daily_user_counts[clean_name] = daily_user_counts.get(clean_name, 0) + 1
                if baselines_data and clean_name not in daily_anomaly_alerts_sent:
                    indiv_stats = baselines_data.get("individual_daily_frequency", {})
                    
                    if name in indiv_stats:
                        threshold = indiv_stats[name].get("anomaly_threshold_2SD", 9999)
                    elif clean_name in indiv_stats:
                        threshold = indiv_stats[clean_name].get("anomaly_threshold_2SD", 9999)
                    elif clean_name == "Unknown":
                        threshold = 0
                    else:
                        threshold = getattr(config, 'NEW_USER_GRACE_THRESHOLD', 5)
                        
                    if daily_user_counts[clean_name] > threshold:
                        send_individual_anomaly_alert(frame, clean_name, daily_user_counts[clean_name], threshold)
                        daily_anomaly_alerts_sent.add(clean_name)
            else:
                active_visits[clean_name]['last_seen'] = now_time

            current_duration = now_time - active_visits[clean_name]['start']
            
            if baselines_data and not active_visits[clean_name]['alert_sent']:
                dur_stats = baselines_data.get("typical_visit_durations", {})
                raw_name = active_visits[clean_name]['raw_name']
                
                if raw_name in dur_stats:
                    threshold = dur_stats[raw_name].get("anomaly_max_duration", 9999)
                elif clean_name in dur_stats:
                    threshold = dur_stats[clean_name].get("anomaly_max_duration", 9999)
                else:
                    threshold = getattr(config, 'DEFAULT_MAX_DURATION', 300) 
                    
                if current_duration > threshold:
                    send_duration_anomaly_alert(frame, clean_name, current_duration, threshold)
                    active_visits[clean_name]['alert_sent'] = True 

        expired_visits = []
        for v_name, v_data in active_visits.items():
            if now_time - v_data['last_seen'] > VISIT_BUFFER:
                final_duration = v_data['last_seen'] - v_data['start']
                update_event_duration(v_data['db_id'], final_duration)
                expired_visits.append(v_name)
                
        for v_name in expired_visits:
            del active_visits[v_name]


        if unauth_found and not auth_found:
            output.on()
            last_unauth_seen_time = time.time() 
            
            if unauth_start is None: # Timing unauthorized detections
                unauth_start = time.time()
                log_event("Timer Started: Unauthorized detection...")
            
            elapsed = time.time() - unauth_start
            if elapsed >= UNAUTH_THRESHOLD:
                send_email_alert(frame, elapsed)
                unauth_start = None 
                
        else:
            output.off()
            if unauth_start is not None:
                time_since_last_seen = time.time() - last_unauth_seen_time
                if time_since_last_seen > RESET_PATIENCE:
                    unauth_start = None

        display_frame = draw_results(frame.copy(), locs, names_found)
        with lock:
            output_frame = display_frame
        
        loop_end = time.time()
        loop_duration = loop_end - loop_start
        perf_frame_count += 1
        
        if (loop_end - perf_last_log_time) > LOG_INTERVAL: # Logging performance metrics to SQLite database system_log table
            elapsed_time = loop_end - perf_last_log_time
            fps = perf_frame_count / elapsed_time
            avg_latency = loop_duration * 1000 
            
            log_system_event_to_db(
                "INFO", 
                "Performance", 
                "Routine metrics logged", 
                f"FPS: {fps:.2f}, Latency: {avg_latency:.1f}ms"
            )
            
            perf_frame_count = 0
            perf_last_log_time = loop_end

        time.sleep(0.01)

    except Exception as e:
        log_event(f"LOOP ERROR: {e}", priority="ALERT")
        log_system_event_to_db("ERROR", "Runtime Error", str(e))
        break

picam2.stop()
output.off()
