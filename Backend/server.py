from flask import Flask, jsonify
from flask_cors import CORS
import os
import json

app = Flask(__name__)
CORS(app)

BASE = os.path.dirname(os.path.abspath(__file__))
RESULTS_FILE = os.path.abspath(
    os.path.join(BASE, "results.json")
)
@app.route("/api/results", methods=["GET"])
def get_findings():
    if not os.path.exists(RESULTS_FILE):
       return jsonify({"error": "results.json not found"}), 404

    with open(RESULTS_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    return jsonify(data)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)