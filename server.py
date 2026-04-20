from flask import Flask, jsonify, request, render_template
import hashlib
import secrets
import string
import random
import time

app = Flask(__name__)
sensor_key_pools = [7, 8, 3, 4, 2, 12, 16, 18, 13]
T_diff = 10000

import hashlib

def compute_d4(idx_hex: str, r1_hex: str, r2_hex: str, b1_hex: str) -> str:
    # convert hex → integers
    idx = int(idx_hex, 16)
    r1 = int(r1_hex, 16)
    r2 = int(r2_hex, 16)

    # 256-bit modular addition
    mod = 2 ** 256
    sum_val = (idx + r1 + r2) % mod

    # back to 32 bytes
    sum_bytes = sum_val.to_bytes(32, 'big')

    # BLAKE2s hash of (b1 || r2)
    h_val = hashlib.blake2s(
        bytes.fromhex(b1_hex) + bytes.fromhex(r2_hex)
    ).digest()

    # XOR
    d4 = bytes(a ^ b for a, b in zip(sum_bytes, h_val))

    return d4.hex()

def int_to_hex_32(n: int) -> str:
    return n.to_bytes(32, 'big', signed=False).hex()

def blake_hash(data: bytes) -> str:
    h = hashlib.blake2s()
    h.update(data)
    return h.hexdigest()

def blake_hash_str(data: str) -> str:
    return blake_hash(data.encode('utf-8'))

def xor_hex_with_hex(hex1: str, hex2: str) -> str:
    b1 = bytes.fromhex(hex1)
    b2 = bytes.fromhex(hex2)
    return bytes([b1[i] ^ b2[i] for i in range(len(b1))]).hex()

sensor_devices = {}
gateway_creds = {}

def generate_id(length=6):
    chars = string.digits  # A-Z, a-z, 0-9
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_unique_id(type_id):
    while True:
        new_id = type_id + generate_id(4)
        if new_id not in sensor_devices:
            return new_id

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
    r1 = random.randint(1, 255)
    KP = random.sample(sensor_key_pools, k=3)

    b1_concat_result = f"{idg}:{gateway_creds["Kg"]}:{r1}"
    b1 = blake_hash_str(b1_concat_result)

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
        d1_concat_hash = blake_hash_str(d1_concat)

        r1 = xor_hex_with_hex(sensor_devices["D1"], d1_concat_hash)
        print(f"R1 from Gateway: {r1}")

        D2_concat = f"{r1}:{T1}:{b0}"
        D2 = blake_hash_str(D2_concat)
        print(f"D2 (gateway): {D2}")
        print(f"D2 (sensor): {sensor_devices["D2"]}")

        if(D2 == sensor_devices["D2"]):
            # Select random number r2 and idx
            r2 = random.randint(1, 255)
            r2_hex = int_to_hex_32(r2)

            kp_len = len(gateway_creds['KP'])
            idx = random.randint(0, kp_len-1)
            idx_hex = int_to_hex_32(idx)

            D3_concat = f"{r1}:{T2}"
            D3_hash_part = blake_hash_str(D3_concat)

            D3 = xor_hex_with_hex(D3_hash_part, r2_hex)
            
            D4_right_concat = f"{b1}:{r2_hex}"
            D4_right = blake_hash_str(D4_right_concat)

            D4 = compute_d4(idx_hex, r1, r2_hex, D4_right)

            D5_concat = f"{idx_hex}:{r2_hex}:{b0}:{r1}"
            D5 = blake_hash_str(D5_concat)

            M2 = { # M2 sends to the Sensor
                "T2": T2,
                "D3": D3,
                "D4": D4,
                "D5": D5
            }
            return jsonify({
                "message": "Success. Completed Step 2 of Authentication",
                "M2": M2
            }), 200
        
        else:
            return jsonify({
                "message": "Unauthorized Communication"
            }), 403
    
    else:
        print(f"T1: {T1}, T2: {T2}")
        print("Timeout. Aborting the communication")
        return jsonify({"message": "Timeout. Aborting communication."}), 408



if __name__ == "__main__":
    app.run(host='172.16.218.128', debug=True)