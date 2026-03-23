from flask import Flask, jsonify, request, render_template
import hashlib
import secrets
import string

app = Flask(__name__)
h = hashlib.blake2s()  # one-way hash function

devices = {}


def generate_id(length=6):
    chars = string.digits  # A-Z, a-z, 0-9
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_unique_id(type):
    while True:
        new_id = generate_id(4)
        if new_id not in devices:
            return type + new_id

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/receive", methods=['POST'])
def receive():
    data = request.get_json()

    aid = data.get("AID")
    kS = data.get("kS")
    r0 = data.get("r0")
    ids = generate_unique_id("SID_")
    devices[ids] = {
        "AID": aid,
        "kS": kS,
        "r0": r0,
    }

    print("Received AID:", aid)
    print("Received Sensor's Secret Key:", kS)
    print("Received Sensor's Random Key: ", r0)
    print("Received Sensor's Identity Key: ", ids)

    concat_results = f"{ids}:{kS}:{r0}"
    print("b0 concat: ", concat_results)

    h.update(concat_results.encode(encoding='utf-8'))  # applying hash to the concat_result
    b0 = h.hexdigest()
    devices[ids]["b0"] = b0
    print(f"b0: {b0}")

    return jsonify({
        "status": "success",
        "message": "AID, r0, b0 received by the Gateway"
    })

@app.route("/receive_from_gateway", methods=['GET'])
def get_from_gateway():
    idg = generate_unique_id("GID_")
    kg =


if __name__ == "__main__":
    app.run(host='172.16.57.46', debug=True)