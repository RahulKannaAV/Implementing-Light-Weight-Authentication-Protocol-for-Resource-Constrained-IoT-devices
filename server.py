from flask import Flask, jsonify, request, render_template
import hashlib
import secrets
import string
import random

app = Flask(__name__)
h = hashlib.blake2s()  # one-way hash function
sensor_key_pools = [7, 8, 3, 4, 2, 12, 16, 18, 13]

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
    r1 = random.randint(1, 999)
    KP = random.sample(sensor_key_pools, k=3)

    b1_concat_result = f"{idg}:{gateway_creds["Kg"]}:{r1}"
    h.update(b1_concat_result.encode(encoding="utf-8"))
    b1 = h.hexdigest()

    print(f"B1 computed from Gateway: {b1}")
    gateway_creds["KP"] = KP
    gateway_creds["b1"] = b1
    gateway_creds["b0"] = request.args.get("b0")

    print(f"Stored in Gateway: {gateway_creds}")
    
    return jsonify({
        "message": "Getting response from Gateway",
        "b1": b1,
        "KP": KP
    })




if __name__ == "__main__":
    app.run(host='172.16.57.46', debug=True)