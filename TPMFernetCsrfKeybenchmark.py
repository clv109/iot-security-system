import subprocess
import time

iterations = 30
#Due to the nature of SPI communication with TPM hardware, limit iterations to under 100 to prevent overload and long wait times

print(f"Starting filesystem benchmark over {iterations} iterations")
print(f"Benchmark for latency of unsealing secret keys from TPM hardware")

# Use time.perf_counter() for purposes of determing most precise benchmark
start_time = time.perf_counter()


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

end_time = time.perf_counter()


total_time = end_time - start_time
avg_time = total_time / iterations * 1000 #Multiply by 1000 to convert to milliseconds

print(f"Total time for {iterations} reads: {total_time} seconds")
print(f"Average latency for a singular read: {avg_time:.4f} milliseconds")

