from flask import Flask, jsonify, request, render_template
import hashlib
import secrets
import string
import random
import time

app = Flask(__name__)
h = hashlib.blake2s()  # one-way hash function
sensor_key_pools = [7, 8, 3, 4, 2, 12, 16, 18, 13]
T_diff = 10000

def blake_hash(data):
    h = hashlib.blake2s()
    h.update(data.encode(encoding="utf-8"))
    hashed_data = h.hexdigest()

    return hashed_data

def xor_hex_with_hex(hex1: str, hex2: str) -> str:
    """
    XOR two hex strings. If different lengths, repeat the shorter one until lengths match.
    """
    b1 = bytes.fromhex(hex1)
    b2 = bytes.fromhex(hex2)
    print(hex1, hex2)
    xor_bytes = bytes([b1[i] ^ b2[i] for i in range(len(b1))])
    return xor_bytes.hex()

sensor_devices = {}
gateway_creds = {}

def generate_id(length=6):
    chars = string.digits  # A-Z, a-z, 0-9
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_unique_id(type):
    while True:
        new_id = generate_id(4)
        if new_id not in sensor_devices:
            return type + new_id

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/reg_1", methods=['POST'])
def receive():
    data = request.get_json()

    aid = data.get("AID")
    kS = data.get("kS")
    r0 = data.get("r0")
    b0 = data.get("b0")
    ids = data.get("IDs")
    sensor_devices = {
        "AID": aid,
        "r0": r0,
        "b0": b0
    }

    print("Received AID:", aid)
    print("Received Sensor's Random Key: ", r0)
    print("Received B0: ", b0)

    return jsonify({
        "status": "success",
        "message": "AID, r0, b0 received by the Gateway"
    })

@app.route("/reg_2", methods=['GET'])
def get_from_gateway():
    idg = generate_unique_id("GID_")
    if "Kg" not in gateway_creds:
        gateway_creds["Kg"] =  "GK_" + generate_id(6)
    r1 = random.randint(1, 256)
    KP = random.sample(sensor_key_pools, k=3)

    b1_concat_result = f"{idg}:{gateway_creds["Kg"]}:{r1}"
    b1 = blake_hash(b1_concat_result)

    print(f"B1 computed from Gateway: {b1}")
    # Registration - Step 3
    
    gateway_creds["KP"] = KP
    gateway_creds["b1"] = b1
    gateway_creds["b0"] = request.args.get("b0")

    print(f"Stored in Gateway: {gateway_creds}")
    
    return jsonify({
        "message": "Getting response from Gateway",
        "b1": b1,
        "KP": KP
    })

@app.route("/auth_1", methods=['POST'])
def get_m1():
    m1 = request.get_json()
    print(f"Auth-1 from Sensor: {m1}")
    sensor_devices["T1"] = m1["T1"]
    sensor_devices["AID"] = m1["AID"]
    sensor_devices["D1"] = m1["D1"]
    sensor_devices["D2"] = m1["D2"]

    return jsonify({
        "status": "success",
        "message": "D1, D2 received from Sensor"
    })

"""
NEED TO TEST THIS

@app.route("/auth_2", methods=["GET"])
def get_m2():
    # Current timestamp in milliseconds
    T2 = int(time.time() * 1000)
    T1 = sensor_devices["T1"]

    if abs(T2 - T1) <= T_diff:
        print("Can proceed the communication")

        AID = sensor_devices["AID"]
        b1 = gateway_creds["b1"]
        b0 = gateway_creds["b0"]

        # 1️⃣ Compute the hash to recover r1
        # Concatenate exactly like the paper (no colons!)
        d1_concat = f"{AID}{b1}{T1}"
        d1_hash_hex = blake2s_hex_sensor(d1_concat)

        # 2️⃣ XOR with D1 from sensor to recover r1
        D1_hex = sensor_devices["D1"]
        r1_hex = xor_hex_strings(D1_hex, d1_hash_hex)
        r1_bytes = bytes.fromhex(r1_hex)

        print(f"R1 from Gateway (hex): {r1_hex}")

        # 3️⃣ Compute D2 to verify
        D2_input = r1_bytes + str(T1).encode("utf-8") + b0.encode("utf-8")
        D2_check = hashlib.blake2s(D2_input).hexdigest()

        print(f"D2 (gateway): {D2_check}")
        print(f"D2 (sensor): {sensor_devices['D2']}")

        if D2_check == sensor_devices["D2"]:
            print("Authentication successful")
            return jsonify({"message": "Authentication Success"})
        else:
            print("Authentication failed")
            return jsonify({"message": "Authentication Failed"}), 401

    else:
        print(f"T1: {T1}, T2: {T2}")
        print("Timeout. Aborting the communication")
        return jsonify({"message": "Timeout"}), 408

"""

@app.route("/auth_2", methods=["GET"])
def get_m2():
    T2 = int(time.time()) * 1000
    T1 = sensor_devices["T1"]

    if(abs(T2 - T1) <= T_diff):
        print("Can proceed the communication")
        AID = sensor_devices["AID"]
        b1 = gateway_creds["b1"]
        b0 = gateway_creds["b0"]

        d1_concat = f"{AID}:{b1}:{T1}"
        d1_concat_hash = blake_hash(d1_concat)

        r1 = xor_hex_with_hex(sensor_devices["D1"], d1_concat_hash)
        print(f"R1 from Gateway: {r1}")

        D2_concat = f"{r1}:{T1}:{b0}"
        D2 = blake_hash(D2_concat)
        print(f"D2 (gateway): {D2}")
        print(f"D2 (sensor): {sensor_devices["D2"]}")

        return jsonify({
            "message": "Success"
        })
    
    else:
        print(f"T1: {T1}, T2: {T2}")
        print("Timeout. Aborting the communication")
        return 



if __name__ == "__main__":
    app.run(host='172.16.57.46', debug=True)