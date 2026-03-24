from flask import Flask, jsonify, request, render_template
import hashlib
import secrets
import string
import random
import time

app = Flask(__name__)

# =========================
# 🔐 CRYPTO HELPERS
# =========================

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

# =========================
# 📦 STORAGE
# =========================

sensor_key_pools = [7, 8, 3, 4, 2, 12, 16, 18, 13]
T_diff = 10000  # ms

sensor_devices = {}
gateway_creds = {}

# =========================
# 🧰 HELPERS
# =========================

def generate_id(length=6):
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def generate_unique_id(prefix: str):
    while True:
        new_id = prefix + generate_id(4)
        if new_id not in sensor_devices:
            return new_id

# =========================
# 🌐 ROUTES
# =========================

@app.route('/')
def home():
    return render_template('test_index.html')

# ---------- REGISTRATION ----------

@app.route("/reg_1", methods=['POST'])
def reg_1():
    data = request.get_json()

    sensor_devices["AID"] = data["AID"]
    sensor_devices["r0"] = data["r0"]
    sensor_devices["b0"] = data["b0"]

    print("Sensor -> Gateway:", sensor_devices)

    return jsonify({"status": "ok"})


@app.route("/reg_2", methods=['GET'])
def reg_2():

    idg = generate_unique_id("GID_")

    if "Kg" not in gateway_creds:
        gateway_creds["Kg"] = "GK_" + generate_id(6)

    # (not used in auth, but kept for structure)
    r1_temp = random.randint(1, 255)

    KP = random.sample(sensor_key_pools, k=3)

    b1 = blake_hash_str(f"{idg}:{gateway_creds['Kg']}:{r1_temp}")

    gateway_creds.update({
        "idg": idg,
        "KP": KP,
        "b1": b1,
        "b0": request.args.get("b0")
    })

    print("Gateway creds:", gateway_creds)

    return jsonify({
        "b1": b1,
        "KP": KP
    })


# ---------- AUTHENTICATION ----------

@app.route("/auth_1", methods=['POST'])
def auth_1():
    data = request.get_json()

    sensor_devices["T1"] = data["T1"]
    sensor_devices["D1"] = data["D1"]
    sensor_devices["D2"] = data["D2"]

    print("Received M1:", data)

    return jsonify({"status": "received"})


@app.route("/auth_2", methods=["GET"])
def auth_2():
    time.sleep(8)
    T2 = int(time.time() * 1000)
    T1 = sensor_devices.get("T1")

    # ⏱️ Timestamp check
    if abs(T2 - T1) > T_diff:
        print("Timeout. Ending the Communication")
        return jsonify({"message": "Timeout"}), 408

    print("Timestamp valid", abs(T2 - T1))

    AID = sensor_devices["AID"]
    b1 = gateway_creds["b1"]
    b0 = gateway_creds["b0"]

    # 1️⃣ Compute H(AID || b1 || T1)
    d1_hash_hex = blake_hash_str(f"{AID}:{b1}:{T1}")

    # 2️⃣ Recover r1
    D1_hex = sensor_devices["D1"]
    r1_hex = xor_hex_with_hex(D1_hex, d1_hash_hex)

    print("Recovered r1:", r1_hex)

    # 3️⃣ Verify D2 (IMPORTANT FIX)
    D2_check = blake_hash_str(f"{r1_hex}:{T1}:{b0}")

    print("D2 (gateway):", D2_check)
    print("D2 (sensor) :", sensor_devices["D2"])

    if D2_check == sensor_devices["D2"]:
        print("✅ Authentication SUCCESS")
        return jsonify({"message": "Authentication Success"})
    else:
        print("❌ Authentication FAILED")
        return jsonify({"message": "Authentication Failed"}), 401


# =========================
# 🚀 RUN
# =========================

if __name__ == "__main__":
    app.run(host='172.16.57.46', port=5000, debug=True)