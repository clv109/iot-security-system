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
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

# IMPORT THE SHARED SETTINGS
import config 

# ==========================================
#        USER CONFIGURATION SECTION
# ==========================================

SENDER_EMAIL = "carsonlv09@gmail.com"
SENDER_PASSWORD = "ivsvcjryptdmjibm"
RECEIVER_EMAIL = "carsonlv09@gmail.com"

# ==========================================
#           MAIN SECURITY LOGIC
# ==========================================

ALERT_COOLDOWN_SECONDS = 10.0
UNAUTHORIZED_DURATION_THRESHOLD = 2.0 #change to change duration of continuos detection of unauthorized person before sending email

last_alert_time = 0
unauthorized_start_time = None

print("[INFO] loading encodings...")
with open("encodings.pickle", "rb") as f:
    data = pickle.loads(f.read())
known_face_encodings = data["encodings"]
known_face_names = data["names"]

picam2 = Picamera2()
picam2.configure(picam2.create_preview_configuration(main={"format": 'XRGB8888', "size": (1920, 1080)}))
picam2.start()

output = LED(17)
cv_scaler = 6

face_locations = []
face_encodings = []
face_names = []
frame_count = 0
start_time = time.time()
fps = 0

def is_quiet_hours():
    """
    Checks if the current time is within the designated quiet hours.
    Returns True if it is quiet hours, False otherwise.
    """
    current_hour = datetime.now().hour
    start = config.QUIET_HOURS_START
    end = config.QUIET_HOURS_END
    
    # Handle overnight ranges (e.g., 22:00 to 06:00)
    if start > end:
        return current_hour >= start or current_hour < end
    else:
        # Handle same-day ranges (e.g., 00:00 to 06:00)
        return start <= current_hour < end

def send_email_alert(image_frame, total_time):
    global last_alert_time
    current_time = time.time()
    
    if (current_time - last_alert_time) > ALERT_COOLDOWN_SECONDS:
        print("Unauthorized person detected. preparing alert...")
        _, image_encoded = cv2.imencode(".jpg", image_frame)
        image_bytes = image_encoded.tobytes()

        msg = MIMEMultipart()
        now = datetime.now()
        
        # --- LOGIC: Check for Quiet Hours ---
        if is_quiet_hours():
            print("!!! QUIET HOURS VIOLATION DETECTED !!!")
            subject = f"URGENT: QUIET HOURS BREACH - Unauthorized Person Detected!"
            body_text = (f"WARNING: An unauthorized person was detected during designated QUIET HOURS ({config.QUIET_HOURS_START}:00 - {config.QUIET_HOURS_END}:00).\n\n"
                         f"Time: {now}\n"
                         f"Duration in view: {total_time:.1f} seconds.\n"
                         f"Please investigate immediately.")
        else:
            subject = 'Security Alert: Unauthorized Person Detected Over 15s!'
            body_text = (f"An unauthorized person remained in view for over the set time in seconds at {now}.\n"
                         f"Total time detected: {total_time:.1f} seconds.")

        msg['Subject'] = subject
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        
        body = MIMEText(body_text)
        msg.attach(body)
        
        image = MIMEImage(image_bytes, name="unauthorized_capture.jpg")
        msg.attach(image)

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
                print(f"Email alert sent! Subject: {subject}")
            last_alert_time = current_time
        except Exception as e:
            print(f"Error: Failed to send email. Reason: {e}")

def process_frame(frame):
    global face_locations, face_encodings, face_names, unauthorized_start_time

    resized_frame = cv2.resize(frame, (0, 0), fx=(1/cv_scaler), fy=(1/cv_scaler))
    rgb_resized_frame = cv2.cvtColor(resized_frame, cv2.COLOR_BGR2RGB)

    face_locations = face_recognition.face_locations(rgb_resized_frame)
    face_encodings = face_recognition.face_encodings(rgb_resized_frame, face_locations, model='large')

    face_names = []
    authorized_face_detected = False
    unauthorized_detected = False

    for face_encoding in face_encodings:
        matches = face_recognition.compare_faces(known_face_encodings, face_encoding, tolerance=0.3)
        name = "Unknown"
        face_distances = face_recognition.face_distance(known_face_encodings, face_encoding)
        best_match_index = np.argmin(face_distances)
        if matches[best_match_index]:
            name = known_face_names[best_match_index]
            # === USE CONFIG LIST ===
            if name in config.AUTHORIZED_NAMES:
                authorized_face_detected = True
        
        # If the face is "Unknown" OR recognized but not in the authorized list
        # === USE CONFIG LIST ===
        if name == "Unknown" or name not in config.AUTHORIZED_NAMES:
             unauthorized_detected = True
             
        face_names.append(name)

    # Logic: If unauthorized person is present AND no authorized person is present to supervise
    if unauthorized_detected and not authorized_face_detected:
        if unauthorized_start_time is None:
            unauthorized_start_time = time.time()
        else:
            total_time = time.time() - unauthorized_start_time
            if total_time >= UNAUTHORIZED_DURATION_THRESHOLD:
                send_email_alert(frame, total_time)
                unauthorized_start_time = None
    else:
        unauthorized_start_time = None

    if unauthorized_detected:
        output.on()
    else:
        output.off()

    return frame

def draw_results(frame):
    for (top, right, bottom, left), name in zip(face_locations, face_names):
        top *= cv_scaler
        right *= cv_scaler
        bottom *= cv_scaler
        left *= cv_scaler
        
        # === USE CONFIG LIST ===
        if name in config.AUTHORIZED_NAMES:
            color = (0, 255, 0)
        else:
            color = (0, 0, 255)

        cv2.rectangle(frame, (left, top), (right, bottom), color, 3)
        cv2.rectangle(frame, (left -3, top - 35), (right+3, top), color, cv2.FILLED)
        font = cv2.FONT_HERSHEY_DUPLEX
        cv2.putText(frame, name, (left + 6, top - 6), font, 1.0, (255, 255, 255), 1)
        
        # === USE CONFIG LIST ===
        if name in config.AUTHORIZED_NAMES:
             cv2.putText(frame, "Authorized", (left + 6, bottom + 23), font, 0.6, color, 1)
        else:
             cv2.putText(frame, "Unauthorized", (left + 6, bottom + 23), font, 0.6, color, 1)

    # --- Display "Quiet Hours" status on screen ---
    if is_quiet_hours():
        cv2.putText(frame, "QUIET HOURS ACTIVE", (20, 60), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)

    return frame

def calculate_fps():
    global frame_count, start_time, fps
    frame_count += 1
    elapsed_time = time.time() - start_time
    if elapsed_time > 1:
        fps = frame_count / elapsed_time
        frame_count = 0
        start_time = time.time()
    return fps

while True:
    try:
        frame = picam2.capture_array()
        frame = cv2.flip(frame, 0)
        processed_frame = process_frame(frame)
        display_frame = draw_results(processed_frame)
        current_fps = calculate_fps()
        cv2.putText(display_frame, f"FPS: {current_fps:.1f}", (display_frame.shape[1] - 150, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
        cv2.imshow('Video', display_frame)
        if cv2.waitKey(1) == ord("q"):
            break
    except Exception as e:
        print(f"Error in loop: {e}")
        break

cv2.destroyAllWindows()
picam2.stop()
output.off()
