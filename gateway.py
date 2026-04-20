from flask import Flask, jsonify, request, render_template
import hashlib, secrets, random, time

app = Flask(__name__)

T_diff = 10000

sensor_devices = {}
gateway_creds = {}

# ===== UTILS =====

def H_str(data: str):
    return hashlib.blake2s(data.encode()).hexdigest()

def H_bytes(data: bytes):
    return hashlib.blake2s(data).digest()

def xor_hex(h1, h2):
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return bytes([b1[i] ^ b2[i] for i in range(len(b1))]).hex()

def int_to_hex_32(n: int):
    return n.to_bytes(32, 'big').hex()

def hex_to_int(h):
    return int(h, 16)

# ===== REGISTRATION STEP 1 =====

@app.route("/reg_1", methods=['POST'])
def reg1():
    data = request.json

    sensor_devices["AID"] = data["AID"]
    sensor_devices["r0"] = data["r0"]
    sensor_devices["b0"] = data["b0"]

    print("\n=== REG-1 ===")
    print(sensor_devices)

    return jsonify({"status": "success"})


# ===== REGISTRATION STEP 2 =====

@app.route("/reg_2", methods=['GET'])
def reg2():
    b0 = request.args.get("b0")

    IDg = "GID_" + str(random.randint(1000,9999))
    Kg = "GK_" + str(random.randint(1000,9999))

    r1 = random.randint(1,255)

    b1 = H_str(f"{IDg}:{Kg}:{r1}")

    KP = random.sample([7,8,3,4,2,12,16,18,13], k=3)

    gateway_creds.update({
        "IDg": IDg,
        "Kg": Kg,
        "b1": b1,
        "b0": b0,
        "KP": KP
    })

    print("\n=== REG-2 ===")
    print(gateway_creds)

    return jsonify({
        "status": "success",
        "b1": b1,
        "KP": KP
    })


# ===== AUTH STEP 1 =====

@app.route("/auth_1", methods=['POST'])
def auth1():
    data = request.json

    sensor_devices["T1"] = data["T1"]
    sensor_devices["AID"] = data["AID"]
    sensor_devices["D1"] = data["D1"]
    sensor_devices["D2"] = data["D2"]

    print("\n=== AUTH-1 RECEIVED ===")
    print(sensor_devices)

    return jsonify({"status": "success"})


# ===== AUTH STEP 2 =====

@app.route("/auth_2", methods=["GET"])
def auth2():

    T2 = int(time.time()*1000)
    T1 = sensor_devices["T1"]

    if abs(T2 - T1) > T_diff:
        return jsonify({"status":"fail","reason":"timeout"}), 408

    AID = sensor_devices["AID"]
    b1 = gateway_creds["b1"]
    b0 = gateway_creds["b0"]

    # ===== RECOVER r1 =====
    d1_hash = H_str(f"{AID}:{b1}:{T1}")
    r1_hex = xor_hex(sensor_devices["D1"], d1_hash)

    print("\nRecovered r1:", r1_hex)

    # ===== VERIFY D2 =====
    D2_calc = H_str(f"{r1_hex}:{T1}:{b0}")

    print("D2 recv:", sensor_devices["D2"])
    print("D2 calc:", D2_calc)

    if D2_calc != sensor_devices["D2"]:
        return jsonify({"status":"fail","reason":"D2 mismatch"}), 403

    print("✅ D2 VERIFIED")

    # ===== GENERATE r2 =====
    r2 = random.randint(1,255)
    r2_hex = int_to_hex_32(r2)

    # ===== SELECT idx =====
    idx = random.randint(0, len(gateway_creds["KP"])-1)
    idx_hex = int_to_hex_32(idx)

    # ===== D3 =====
    D3_hash = H_str(f"{r1_hex}:{T2}")
    D3 = xor_hex(D3_hash, r2_hex)

    # ===== D4 ===== (simplified verifiable)
    D4 = H_str(f"{idx_hex}:{r1_hex}:{r2_hex}:{b1}")
    # ===== D5 =====
    D5 = H_str(f"{idx_hex}:{r2_hex}:{b0}:{r1_hex}")

    # ===== SESSION KEY =====
    SK = H_str(f"{r1_hex}:{r2_hex}:{b0}")

    print("\n=== AUTH-2 SEND ===")
    print("r2:", r2_hex)
    print("idx:", idx_hex)
    print("D3:", D3)
    print("D4:", D4)
    print("D5:", D5)
    print("SESSION KEY:", SK)

    return jsonify({
        "status": "success",
        "M2": {
            "T2": T2,
            "idx": idx_hex,
            "D3": D3,
            "D4": D4,
            "D5": D5
        }
    })


# ===== AUTH STEP 3 (OPTIONAL FINAL VERIFY) =====

@app.route("/auth_3", methods=["POST"])
def auth3():
    data = request.json

    print("\n=== FINAL CONFIRMATION FROM SENSOR ===")
    print(data)

    return jsonify({"status":"mutual_auth_success"})

@app.route('/')
def home():
    return render_template('client_ui.html')

if __name__ == "__main__":
    app.run(host='172.16.218.128', debug=True)