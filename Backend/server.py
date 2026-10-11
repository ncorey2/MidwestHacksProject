
from flask import Flask, jsonify
from pathlib import Path
import json

app = Flask(__name__)

RESULTS_PATH = Path(__file__).resolve().parent / "results.json"


@app.get("/api/results")
def get_results():
    try:
        # Read the latest file each time this endpoint is requested
        with open(RESULTS_PATH, "r", encoding="utf-8") as file:
            results = json.load(file)

        return jsonify(results)

    except FileNotFoundError:
        return jsonify({"error": "results.json not found"}), 404

    except json.JSONDecodeError:
        return jsonify({"error": "Results are being updated. Try again."}), 503


if __name__ == "__main__":
    app.run(debug=True)
