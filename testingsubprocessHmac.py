# Testing the functionality of generating pseudonyms for identifiers via subprocess. Iterate through the list and pseudonymize each element, assign it key:value pair in a dictionary 
import subprocess

identifiers = ["Car_Lv", "Joker"]
map = {}

loading_hmac = subprocess.run(
        ["tpm2_load", "-C", "0x81010001", "-u", "TPMhmac.pub", "-r", "TPMhmac.priv", "-c", "TPMhmac.ctx"],
        capture_output=True, text=True
    )


for name in identifiers:
	hmac_process = subprocess.run(
            ["tpm2_hmac", "-c", "TPMhmac.ctx", "--hex"],
            input=name,
            capture_output=True, text=True
        )
	map[name] = hmac_process.stdout.strip()

print(map)

