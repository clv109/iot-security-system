# Generate master encryption key
from cryptography.fernet import Fernet
import os

def generate_and_save_key():
    print("[INFO] Forging a new cryptographic key...")

    # Generate Fernet key
    key = Fernet.generate_key()

    # Save the key to 'secret.key'
    # Use "wb" (write binary) because the key is in byte format
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

    print("[SUCCESS] Master key successfully generated and saved to 'secret.key'")

    # Print a snippet to user
    print(f"[KEY PREVIEW] {key.decode('utf-8')}")
    print("[WARNING] Do not share this key! Your Flask app and Camera script will read it automatically.")

if __name__ == "__main__":
    generate_and_save_key()
