import time
from dotenv import dotenv_values

ENV_Path = "secretcredentials.env"
iterations = 5000


print(f"Starting filesystem benchmark over {iterations} iterations")
print(f"Benchmark for latency of extracting secret keys from .env file into the system")

# Use time.perf_counter() for purposes of determing most precise benchmark
start_time = time.perf_counter()

for _ in range(iterations):
	secrets = dotenv_values(ENV_Path)
	fernet_key = secrets.get("FLASK_SECRET_KEY")
	csrfbiometric_key= secrets.get("BIOMETRIC_KEY")


end_time = time.perf_counter()


total_time = end_time - start_time
avg_time = total_time / iterations * 1000 #Multiply by 1000 to convert to milliseconds


print(f"Total time for {iterations} reads: {total_time} seconds")
print(f"Average latency for a singular read: {avg_time:.4f} milliseconds")


