import random
import hashlib
import time

# Paper Title: Lightweight Authentication Protocol for M2M
# Communications of Resource-Constrained Devices
# in Industrial Internet of Things

# REGISTRATION
# Step 1
r0 = random.randint(1, 10000)
IDs = "D101"  # Sensor's ID key
kS = "SK246"  # Sensor's Secret Key
AID = "SEN_746"
T_diff = 10
sensor_key_pools = [7, 8, 3, 4, 2, 12, 16, 18, 13]

concat_results = IDs + kS + str(r0)  # IDs || kS || r0
h = hashlib.blake2s()  # one-way hash function
h.update(concat_results.encode(encoding='utf-8'))  # applying hash to the concat_result
b0 = h.hexdigest()  # getting the hash result b0

sensor_send_data = {"AID": AID, "r0": r0, "b0": b0}
print(f"Sensor to Gateway {sensor_send_data}")

# Step 2
r1 = random.randint(1, 10000) # Random number chosen by gateway
IDg = "G273"
kG = "GK796"

gateway_concat = IDg + kG + str(r1)  # IDg || kG || r1
h.update(gateway_concat.encode(encoding="utf-8"))
b1 = h.hexdigest()  # gateway concatenation hash value generation
KP = random.sample(sensor_key_pools, k=3)

gateway_send_data = {"b1": b1, "KP": KP}
print(f"Gateway to Sensor {gateway_send_data}")

# Step 3
store_data = {"b0": b0, "b1": b1, "KP": KP}
print(f"Sensor and Gateway stores {store_data}")



# AUTHENTICATION
# Step 1
r1 = random.randint(1, 10000)
T1 = int(time.time())
concat_results_d1 = AID + store_data["b1"] + str(T1)
h.update(concat_results.encode(encoding="utf-8"))
d1_hash = h.hexdigest()
D1 = int(d1_hash, 16) ^ r1

concat_results_d2 = str(r1) + str(T1) + store_data["b0"]
h.update(concat_results_d2.encode(encoding="utf-8"))
D2 = h.hexdigest()

M1 = {"T1": T1, "AID": AID, "D1": D1, "D2": D2}
print(f"Sending to Gateway: {M1}")

# Step 2

