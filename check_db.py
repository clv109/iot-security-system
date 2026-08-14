import sqlite3
import os
import sys

def inspect_database():
    # 1. Ask the user for the filename
    # We check if they typed it in the terminal (e.g., "python inspect.py alertlog.db")
    if len(sys.argv) > 1:
        db_file = sys.argv[1]
    else:
        # Otherwise, we ask for it nicely
        db_file = input("Enter database filename (e.g., surveillance.db or alertlog.db): ").strip()

    # 2. Check if file exists
    if not os.path.exists(db_file):
        print(f"\n[ERROR] Database file '{db_file}' not found!")
        print("Make sure you are in the correct folder and the file name is correct.")
        return

    # 3. Connect to the database
    print(f"\n[INFO] Connecting to {db_file}...")
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
    except sqlite3.Error as e:
        print(f"[CRITICAL] Could not connect to database: {e}")
        return

    # 4. List all tables
    print("\n--- TABLES FOUND ---")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    if not tables:
        print("No tables found inside this database.")
        conn.close()
        return
    
    # Extract table names from the tuples
    table_names = [t[0] for t in tables]
    for name in table_names:
        print(f"- {name}")

    # 5. Check contents of EACH table found
    for table_name in table_names:
        # Skip the internal SQLite sequence table (used for auto-incrementing IDs)
        if table_name == "sqlite_sequence":
            continue

        print(f"\n--- CONTENT OF TABLE: '{table_name}' ---")
        try:
            # We select everything from the current table
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
            
            if len(rows) == 0:
                print(f"Table '{table_name}' exists but is EMPTY.")
            else:
                print(f"Found {len(rows)} entries:")
                
                # Get and print column names for better readability
                if cursor.description:
                    column_names = [description[0] for description in cursor.description]
                    print(f"Columns: {column_names}")
                
                print("-" * 50)
                # Print the rows
                for row in rows:
                    print(row)
                    
        except sqlite3.Error as e:
            print(f"Error reading table {table_name}: {e}")
    
    conn.close()
    print("\n[INFO] Inspection complete.")

if __name__ == "__main__":
    inspect_database()
