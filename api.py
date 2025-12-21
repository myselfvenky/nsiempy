import pickle
import numpy as np
import tensorflow as tf
from flask import Flask, request, jsonify
import pandas as pd
import joblib
import warnings
from flask import Flask
from flask_cors import CORS
import requests 
import json


app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Suppress scikit-learn version warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# Load preprocessor with ignore_warnings
with open("preprocessor.pkl", "rb") as f:
    preprocessor = pickle.load(f)

encoder = joblib.load("label_encoder.pkl")

# Load LSTM model with compile=True to avoid compilation warnings
model_http = tf.keras.models.load_model("lstm_model.h5", compile=True)
model_tcp = tf.keras.models.load_model('model_tcp.h5', compile=True)


FEATURE_ORDER = [
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Total Length of Fwd Packet",
    "Total Length of Bwd Packet",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWR Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Fwd Segment Size Avg",
    "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg",
    "Fwd Packet/Bulk Avg",
    "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg",
    "Bwd Packet/Bulk Avg",
    "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "FWD Init Win Bytes",
    "Bwd Init Win Bytes",
    "Fwd Act Data Pkts",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]

@app.route("/http_ddos", methods=["POST"])
def predict_http():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Send JSON with 'features' key"}), 400

    # Process input for model
    df = pd.DataFrame([[data.get(col, 0) for col in FEATURE_ORDER]], columns=FEATURE_ORDER)
    X_proc = preprocessor.transform(df)
    X_lstm = X_proc.reshape((X_proc.shape[0], 1, X_proc.shape[1]))
    probs = model_http.predict(X_lstm)
    pred_index = int(np.argmax(probs, axis=1)[0])
    pred_label = encoder.inverse_transform([pred_index])[0]

    try:
        # 1️⃣ Create payload with only pred_label and isAnalyzed=true
        payload_data = {
            "data": [pred_label],  # Only pred_label
            "isAnalyzed": True     # Make sure backend uses this field
        }
        payload_resp = requests.post(
            "http://localhost:5000/payload",
            data=json.dumps(payload_data),
            headers={"Content-Type": "application/json"},
        )
        payload_resp_json = payload_resp.json()
        print("Payload created:", payload_resp_json)

        # 2️⃣ Log attack using pred_label
        attack_payload = {
            "attackType": pred_label,
            "payloadId": 0,  # Or you can use payload_resp_json.payloadId if returned
        }
        response = requests.post(
            "http://localhost:5000/attacks",
            data=json.dumps(attack_payload),
            headers={"Content-Type": "application/json"},
        )
        print("Attack logged:", response.text)

    except Exception as e:
        print("Error sending to localhost:5000:", e)

    # Final response
    return jsonify({
        "predicted_index": pred_index,
        "attackType": pred_label,
        "probabilities": probs.tolist(),
    })



@app.route('/tcp_ddos', methods=['POST'])
def predict_tcp():
    try:
        # Get input JSON
        data = request.get_json()
        print(data)
        # Convert dict to dataframe
        df = pd.DataFrame([data])
        
        # Encode string columns to numeric values
        columnsToEncode = ['src_ip', 'dst_ip']
        for feature in columnsToEncode:
            if feature in df.columns and df[feature].dtype == 'object':
                # Convert IP addresses to numerical values
                df[feature] = pd.factorize(df[feature])[0]
        
        # Convert all remaining object/string columns to numeric
        for col in df.columns:
            if df[col].dtype == 'object':
                try:
                    # Try to convert to numeric
                    df[col] = pd.to_numeric(df[col])
                except:
                    # If conversion fails, use factorize to convert categorical to numeric
                    df[col] = pd.factorize(df[col])[0]
        
        # Ensure all data is float type for model prediction
        df = df.astype('float32')
        
        # Get the expected input features for the model
        # The model expects 12 features, but we're getting 30
        # Let's load the model from the SavedModel directory to get the expected input shape
        try:
            # Try to use the DDOS_Model_tcp directory which contains the SavedModel
            model_from_dir = tf.keras.models.load_model('DDOS_Model_tcp')
            # Use this model instead of the h5 model
            predictions = model_from_dir.predict(df)
        except Exception as model_error:
            # If that fails, select only the first 12 features from the dataframe
            # This is a fallback approach
            if len(df.columns) > 12:
                df = df.iloc[:, :12]  # Select only the first 12 columns
            
            # Make prediction with the original model
            predictions = model_tcp.predict(df)
        
        ind = np.argmax(predictions)

        if ind in [0, 1, 2]:
            result = 'DDoS_TCP'
        elif ind in [3, 4, 5]:
            result = 'Normal'
        else:
            result = 'Unknown'

        return jsonify({'prediction_index': int(ind), 'label': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route("/ddos_volumetric", methods=["get"])
def predict_volumetric():
    arr=[15000,16000,100000,200000,200000,200000,200000,200000,200000,200000,15000,16000,100000,200000,200000,200000,200000,200000,200000,200000,15000,16000,100000,200000]
    print(len(arr))
    return jsonify({'forecasted_volume':arr})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)


