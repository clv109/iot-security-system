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

SENDER_EMAIL = "carsonlv09@gmail.com"
SENDER_PASSWORD = "ivsvcjryptdmjibm"
RECEIVER_EMAIL = "carsonlv09@gmail.com"

ALERT_COOLDOWN_SECONDS = 10.0
UNAUTHORIZED_DURATION_THRESHOLD = 15.0

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
authorized_names = ["CarsonLv"]

def send_email_alert(image_frame, total_time):
    global last_alert_time
    current_time = time.time()
    if (current_time - last_alert_time) > ALERT_COOLDOWN_SECONDS:
        print("Unauthorized person detected for extended time. Sending email alert...")
        _, image_encoded = cv2.imencode(".jpg", image_frame)
        image_bytes = image_encoded.tobytes()

        msg = MIMEMultipart()
        msg['Subject'] = 'Security Alert: Unauthorized Person Detected Over 15s!'
        msg['From'] = SENDER_EMAIL
        msg['To'] = RECEIVER_EMAIL
        now = datetime.now()
        body = MIMEText(f"An unauthorized person remained in view for over 15 seconds at {now}. Total time detected: {total_time:.1f} seconds.")
        msg.attach(body)
        image = MIMEImage(image_bytes, name="unauthorized_duration_capture.jpg")
        msg.attach(image)

        try:
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(SENDER_EMAIL, SENDER_PASSWORD)
                server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
                print("Email alert sent successfully!")
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
            if name in authorized_names:
                authorized_face_detected = True
        else:
            unauthorized_detected = True
        face_names.append(name)

    if unauthorized_detected:
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
        cv2.rectangle(frame, (left, top), (right, bottom), (244, 42, 3), 3)
        cv2.rectangle(frame, (left -3, top - 35), (right+3, top), (244, 42, 3), cv2.FILLED)
        font = cv2.FONT_HERSHEY_DUPLEX
        cv2.putText(frame, name, (left + 6, top - 6), font, 1.0, (255, 255, 255), 1)
        if name in authorized_names:
            cv2.putText(frame, "Authorized", (left + 6, bottom + 23), font, 0.6, (0, 255, 0), 1)
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
    frame = picam2.capture_array()
    frame = cv2.flip(frame, 0)
    processed_frame = process_frame(frame)
    display_frame = draw_results(processed_frame)
    current_fps = calculate_fps()
    cv2.putText(display_frame, f"FPS: {current_fps:.1f}", (display_frame.shape[1] - 150, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    cv2.imshow('Video', display_frame)
    if cv2.waitKey(1) == ord("q"):
        break

cv2.destroyAllWindows()
picam2.stop()
output.off()
