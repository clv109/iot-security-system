# Run this file ONCE via your terminal to safely inject your first Admin user!
from newverybestmainapp import app, db, User, bcrypt

# --- SET YOUR CREDENTIALS HERE ---
# These are the credentials you will type into the login screen.
VIEWER_USERNAME = "Guest1"
VIEWER_PASSWORD = "mach10"

def create_viewer():
    with app.app_context():
        # 1. Check if the user already exists in the SQLite database
        existing_user = User.query.filter_by(username=VIEWER_USERNAME).first()
        
        if existing_user:
            print(f"[INFO] User '{VIEWER_USERNAME}' already exists in the database!")
        else:
            # 2. Run the plain text password through the Bcrypt meat grinder
            hashed_password = bcrypt.generate_password_hash(VIEWER_PASSWORD).decode('utf-8')
            
            # 3. Create the user object. 
            # Notice we save 'hashed_password', NOT 'VIEWER_PASSWORD'!
            new_user = User(
                username=VIEWER_USERNAME, 
                password_hash=hashed_password, 
                role="Viewer"
            )
            
            # 4. Save to the database
            db.session.add(new_user)
            db.session.commit()
            
            print(f"[SUCCESS] Guest user '{VIEWER_USERNAME}' created securely.")
            print(f"[INFO] The stored database hash looks like this: {hashed_password[:25]}...")
            print("[INFO] You can now start your Flask server and log in!")

if __name__ == "__main__":
    create_viewer()
