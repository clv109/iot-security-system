import subprocess
iterations = 1

for _ in range(iterations):
	loadingFernet = subprocess.run(
		["tpm2_load", "-C","0x81010001", "-u","Fernetkey.pub", "-r","Fernetkey.priv", "-c","Fernetkey.ctx"],
		capture_output=True, text=True #Load Fernet key priv/pub file into TPM
)
	Fernet = subprocess.run(
		["tpm2_unseal", "-c","Fernetkey.ctx"], #Unseal Fernet key
		capture_output=True, text=True
)

	loadingCSRF = subprocess.run(
		["tpm2_load", "-C","0x81010001", "-u","HMACcsrf.pub", "-r","HMACcsrf.priv", "-c","HMACcsrf.ctx"],
		capture_output=True, text=True #Load CSRF key priv/pub file into TPM
)
	CSRF = subprocess.run(
		["tpm2_unseal", "-c","HMACcsrf.ctx"], #Unseal CSRF key
		capture_output=True, text=True
)
	cleanFernet = Fernet.stdout.strip()
	print(cleanFernet)
	cleanCSRF = CSRF.stdout.strip()
	print(cleanCSRF)
