

import sqlite3
import subprocess


# First need to find the personal identifier and pseudonym associated with it before rewriting in the SQLite database
def extract_identifiers():
    """Unseal the personal identifiers from the TPM2.0 hardware"""
    identity_list = []

    # Load identifiers into TPM
    loading_identifiers = subprocess.run(
        ["tpm2_load", "-C","0x81010001", "-u","identifiers.pub", "-r","identifiers.priv", "-c","identifiers.ctx"],
        capture_output=True, text=True
    )

    #Ensure loading has occured without issue
    if loading_identifiers.returncode != 0:
        print(f"[ERROR] Failed to load identifiers: {loading_identifiers.stderr}")
        return None

    # Unseal identifiers
    identity = subprocess.run(
        ["tpm2_unseal", "-c","identifiers.ctx"],
        capture_output=True, text=True
    )

    if identity.returncode == 0: #Ensure identifiers properly extracted
        for line in identity.stdout.split('\n'):
            cleaned_name = line.strip() 
            if cleaned_name:
                identity_list.append(cleaned_name) # Add identifiers to returned list

    return identity_list

def establish_pseudonyms(name_list): # Parameter: identity_list, list containing personal identifiers to be pseudoynmized
    mappings = {} # establish dictionary for simple key:value pair to relate pseudoynms to personal identifiers

    # Load the TPM's HMAC key into the TPM 2.0 hardware
    load_hmac = subprocess.run(
    ["tpm2_load", "-C","0x81010001", "-u","TPMhmac.pub", "-r","TPMhmac.priv", "-c","TPMhmac.ctx"],
    capture_output=True, text=True
)

    #Ensure loading has occured without issue
    if load_hmac.returncode != 0:
            print(f"[ERROR] Failed to load TPM HMAC key: {load_hmac.stderr}")
            return None

    for name in name_list: # Loop through all of the identifiers 
            pseudonym = subprocess.run(
            ["tpm2_hmac", "-c","TPMhmac.ctx", "--hex"],
            input=name, capture_output=True, text=True # No need to echo, use input=name instead. Performs the same action as echo by piping elements of names into tpm2_hmac to be pseudonymized
            )

            if pseudonym.returncode == 0: # Ensure pseudonyms created without issue
                        pseudonym_name  = pseudonym.stdout.strip() # Create dictionary mapping with person's name as key, then name's pseudonym as value
                        mappings[name] = pseudonym_name # Key: personal identifier, value: the generated pseudonym
                        mappings[name.replace("_", " ")] = pseudonym_name
			# Add to dictionary with clean name with the underscore removed to simplify later functions during baseline calculations
            else:
                    print(f"[ERROR] Pseudonym generation failed for {name}: {pseudonym.stderr}")

    return mappings


print("Loading TPM personal identifier-pseudonym mapping")


# Set up the pseudonym mappings
names = extract_identifiers()
pseudonym_mappings = establish_pseudonyms(names)

print("Connecting to SQLite database")
conn = sqlite3.connect('surveillance.db')
cursor = conn.cursor()

rows_updated = 0

for plaintext_name, pseudo in pseudonym_mappings.items(): # Loop through each key-value pair and update from personal_identifier to pseudonym
	cursor.execute("""
		UPDATE detection_event
		SET person_name = ?
		WHERE person_name = ?""", (pseudo, plaintext_name)) # supposed to be pseudo is the replacement to be SET, plainttext_name is WHERE to be replaced
	rows_updated = rows_updated + cursor.rowcount # rowcount keeps track of the number of rows modified by the last UPDATE statement

conn.commit()
conn.close()

print(f"Migration of personal identifiers to pseudonyms completed for {rows_updated} rows")
