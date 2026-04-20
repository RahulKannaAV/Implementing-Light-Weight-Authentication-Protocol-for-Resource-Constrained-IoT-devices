from flask import Flask, jsonify, request, render_template, session
import hashlib, secrets, random, time

app = Flask(__name__)
app.secret_key = "is_project_session_lakd"

T_diff = 10000
session_interval = 300*1000 # 5 minutes

sensor_devices = {}
gateway_creds = {}

session_details = {
    "all_sessions": {}
}


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

# Check whether the sensor device needs one
@app.route("/check-session", methods=['POST'] )
def check_for_session():
    print(session)
    M_sensor = request.json
    print(M_sensor)

    # DEVICE ID presence check
    if not M_sensor.get("device_hash"):

        return jsonify({
            "message": "Needs to authenticate",
            "authenticate": True
        })

    device_hash_from_sensor = M_sensor["device_hash"]

    # Session ID presence check
    if not session["all_sessions"].get(device_hash_from_sensor):
        print("Absence of Session ID")
        return jsonify({
            "message": "Needs to authenticate because of absence of Session ID",
            "authenticate": True
        })

    device_session = session["all_sessions"][device_hash_from_sensor]
    print(f"Device: {device_session}")

    # Further process
    if M_sensor.get("sensor_session_details"):
        sensor_id_from_sensor = M_sensor["sensor_session_details"]["SID"]

        print(f"Sent by Sensor: {M_sensor["sensor_session_details"]}")

        if(not device_session.get("SID")):
            return jsonify({
                "message": "Needs to authenticate because of absence of Device Session ID",
                "authenticate": True
            })


    print("Need to check more")
    device_session_details = device_session["SID"]

    print(device_session)
    T_now = int(time.time() * 1000)

    # Expiration check
    if(T_now > device_session["expiry_time"]):
        session["all_sessions"].pop(device_hash_from_sensor)

        return jsonify({
            "message": "Needs to authenticate because of Time limit exceeded",
            "authenticate": True
        })

    # Replay attack
    if(abs(T_now - device_session["last_attempted"]) < 10):

        return jsonify({
            "message": "Replay attack suspicion. Try again",
            "authenticate": True
        })

    # Max attempts reached
    if(device_session["auth_attempts"] > 3):
        session["all_sessions"].pop(device_hash_from_sensor)

        return jsonify({
            "message": "Max attempts reached. Please do the full LAKD Authentication procedure",
            "authenticate": True
        })

    # Verifying session now
    print(gateway_creds)
    session_key_gateway = gateway_creds["session_key"]
    T = M_sensor['T']
    device_hash = M_sensor['device_hash']
    D_fast_sensor = M_sensor['D_fast']

    D_fast_gateway = H_str(f"{session_key_gateway}:{device_session_details}:{T}:{device_hash}")

    print(f"D_fast (sensor): {D_fast_sensor}")
    print(f"D_fast (gateway): {D_fast_gateway}")

    if(D_fast_sensor != D_fast_gateway):
        session["all_sessions"].pop(device_hash_from_sensor)

        return jsonify({
            "message": "Device verification failed. Session aborted. Retry the LAKD authentication",
            "authenticate": True
        })



    print("Continue the previous session")
    return jsonify({
        "message": "Session already exists. Connecting to it",
        "authenticate": False
    })
# ===== REGISTRATION STEP 1 =====

@app.route("/reg_1", methods=['POST'])
def reg1():
    data = request.json

    sensor_devices["AID"] = data["AID"]
    sensor_devices["r0"] = data["r0"]
    sensor_devices["b0"] = data["b0"]

    gateway_creds["device_hash"] = data["device_hash"]

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
    gateway_creds["r1"] = r1_hex

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
    gateway_creds["r2"] = r2_hex

    # ===== SELECT idx =====
    idx = random.randint(0, len(gateway_creds["KP"])-1)
    idx_hex = int_to_hex_32(idx)
    gateway_creds["idx"] = idx_hex

    # ===== D3 =====
    D3_hash = H_str(f"{r1_hex}:{T2}")
    D3 = xor_hex(D3_hash, r2_hex)

    # D4 - new operation D4 = (idx ⊕ r1 ⊕ r2) ⊕ h(b1 || r2)
    D4 = xor_hex(xor_hex(xor_hex(idx_hex, r1_hex), r2_hex), H_str(f"{b1}:{r2_hex}"))
    print(f"Updated D4: {D4}")

    # D4 = H_str(f"{idx_hex}:{r1_hex}:{r2_hex}:{b1}")

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
        },
        "Session": session_details
    })


# ===== AUTH STEP 3 (OPTIONAL FINAL VERIFY) =====
@app.route("/auth_3", methods=["POST"])
def auth3():
    data = request.json

    print("\n=== STEP 3 CONFIRMATION FROM SENSOR ===")
    print(data)

    T4 = int(time.time() * 1000)
    M3 = data['M3']

    sensor_devices["T3"] = M3["T3"]
    sensor_devices["D6"] = M3["D6"]

    return jsonify({"status": "Auth - Step 3 done"})


@app.route("/auth_4", methods=["GET"])
def auth4():
    print("\n=== STEP 4 SENDING RESPONSE TO SENSOR ===")

    T4 = int(time.time() * 1000)

    T3 = sensor_devices["T3"]
    if(abs(T4 - T3) > T_diff):
        print("Authentication - Step 4 Timeout exceeded")
        return

    b1 = gateway_creds["b1"]
    r1 = gateway_creds["r1"]
    r2 = gateway_creds["r2"]
    idx = gateway_creds["idx"]
    KP = gateway_creds["KP"]

    D6 = sensor_devices["D6"]
    D6_calc = H_str(f"{b1}:{r1}:{T3}:{r2}:{KP[int(idx)]}")

    print(f"D6 (Sensor) : {D6}")
    print(f"D6 (calculated from Gateway) : {D6_calc}")

    if(D6 != D6_calc):
        print("D6 verification failed")
        return

    b0 = sensor_devices["b0"]
    D7 = H_str(f"{b0}:{r1}:{T4}:{r2}:{KP[int(idx)]}")
    gateway_creds["D7"] = D7
    print(f"D7: {D7}")

    AID = sensor_devices["AID"]
    SK = H_str(f"{r1}:{r2}:{AID}:{KP[int(idx)]}")
    gateway_creds["session_key"] = SK
    print(f"Session Key: {SK}")

    return jsonify({"status":"mutual_auth_success",
                    "M4": {
                        "T4": T4,
                        "D7": D7
                    }})

@app.route("/verify-session", methods=['POST'])
def verify_auth_session():
    session_details.clear()
    sensor_computed_data = request.json
    session_key_gateway = gateway_creds["session_key"]
    session_key_sensor = sensor_computed_data["session_key"]
    sensor_device_hash = sensor_computed_data["device_hash"]

    print(f"Device Hash: {sensor_device_hash}")

    if(session_key_gateway != session_key_sensor):
        return jsonify({
            "message": "Session Key verification failed. Aborting the authentication"
        }), 401

    print("Session verified successfully")

    AID = sensor_devices["AID"]
    r1_hex = gateway_creds["r1"]
    r2_hex = gateway_creds["r2"]
    T_now = int(time.time() * 1000)

    SID_concat = f"{AID}:{r1_hex}:{r2_hex}"
    SID = H_str(SID_concat)

    all_sessions = session.get("all_sessions", {})

    if sensor_device_hash in all_sessions:
        print("Already there")
        all_sessions[sensor_device_hash]["expiry_time"] += session_interval
        all_sessions[sensor_device_hash]["auth_attempts"] += 1
        all_sessions[sensor_device_hash]["last_attempted"] = T_now


    else:
        session_details["expiry_time"] = T_now + session_interval
        session_details["auth_attempts"] = 1
        session_details["SID"] = SID
        session_details["last_attempted"] = T_now

        all_sessions[sensor_device_hash] = session_details

    print(f"Current Session details: {session_details}")
    print(f"All Sessions: {all_sessions}")

    session["all_sessions"] = all_sessions
    return jsonify({"status": "Created session successfully",
                    "session_info": session_details})

@app.route('/')
def home():
    return render_template('client_ui.html')

LOCALHOST = "172.16.218.128"
if __name__ == "__main__":
    app.run(host=LOCALHOST, debug=True, use_reloader=False)