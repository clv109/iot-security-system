# IoT Security Platform

An edge-computing surveillance system built on a Raspberry Pi. This platform goes **beyond a typical camera surveillance system** by utilizing real time facial recognition, user alert mechanisms, predictive statistical anomaly detection, and a highly secure web dashboard.

## Key Features:
- **Real-Time Facial Recognition:** Process live video feeds using OpenCV to differentiate between authorized users and unknown individuals. The capability to register users, who can upload facial images, occurs through training encrypted facial encodings by the system.
- **Predictive Occupancy Engines:** Using APScheduler, the system automatically calculates rolling mathematical baselines (average and Stdev) to predict expected room occupancy, individualized norms, and flag behavioral anomalies.
- **User Controlled Mechanisms:** Provide users with significant control over the system through customizable quiet hours, anonymized mode, and data retention settings.
- **Data Management:** Utilizing SQLite databases, nearly every output of the system is logged to a secure database. Includes Audit Logs for significant system events, Detection Event Log for camera observations, System Report Log for sent emails, and much more. 
- **Hardware Privacy Masking:** Dynamic privacy zones that are adjustable by the user apply a Gaussian blur to sensitive regions before processing the video feed
- **Secure Web Dashboard:** A Flask-based UI featuring Socket.IO for instantaneous communication, asynchronous API fetching, Chart.js data visualization, and an abundant trove of information. Secured by a login screen that gives administrators full access to all system features while restricting viewers to basic functionalities.
- **Automated Reporting:** A background scheduling engine that generates comprehensive emails with daily, weekly, and monthly security audits.

## System Security Architecture:
- **Encrypted Biometrics:** Facial encodings saved to encodings.pickle are all encrypted using Fernet-based encryption. Only these encrypted versions of sensitive data are ever saved to the Pi's hard drive.
- **Strict Authentication:** Dashboard access is locked behind Flask-Login with Bcrypt password hashing and CSRF token handshakes. Only the hashed versions of passwords are ever stored on the database.
- **Data Retention Manager:** Automated CRON jobs routinely delete outdated SQLite detection events and system logs to minimize data footprint.
- **Safe Repository:** Biometric datasets, email passwords, and cryptographic keys are excluded via .gitignore and managed locally on the Pi through environment variables.
- **Prevent Malicious Intrusions:** Fail2ban and UFW Firewalls secure ports and block IP addresses that attempt to use brute force password guessing attempts. SSH uses a key-based login system to reduce the risk of accessing the system from a compromised password.
- **HTTPS-Based System:** System runs on HTTPS with the installation of pyOpenSSL and sl_context='adhoc' is used on Flask backend to generate its own certificate. 

 

Hence the best security practices, biometric data and environment variables that can potentially compromise security are not included in the repository. 

## Running the System: 
In the main folder, run this command to boot up the system:
```bash
python3 Backend_App.py
```

## Overall Project Structure and File Index:
### Core Files
- **Backend_App.py:**
Acts as the central Flask backend. It handles the HTTPS routing, secure API endpoints, SQLite database tables, login routing, APScheduler background tasks, statistical baselines, periodic comprehensive emails, and data retention.
- **Camera_Script.py:**
Manages the hardware camera and data associated with it. Runs the OpenCV camera inference loop, applies hardware privacy zones, streams raw video frames to local port, and generates anomaly emails.
- **config.py:** Centralized configuration module that houses algorithmic grace periods, 
