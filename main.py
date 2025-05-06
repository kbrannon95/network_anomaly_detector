import os
import sys
import pandas as pd
import numpy as np
import argparse
from scapy.all import rdpcap
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

# --- Ensure proper usage and create output directory ---
if len(sys.argv) < 3:
    print("Usage: python main.py <pcap_directory> <output_directory>")
    sys.exit(1)

pcap_directory = sys.argv[1]
output_directory = sys.argv[2]
os.makedirs(output_directory, exist_ok=True)

def extract_features_scapy(pcap_path, max_packets=500):
    packets = rdpcap(pcap_path)
    features = []
    timestamps = []

    for i, packet in enumerate(packets[:max_packets]):
        try:
            length = len(packet)
            time = float(packet.time)
            proto = packet.payload.name
            proto_id = hash(proto) % 1000
            features.append([length, proto_id])
            timestamps.append(time)
        except Exception:
            continue

    df = pd.DataFrame(features, columns=['length', 'protocol'])
    inter_arrival_times = np.diff(timestamps, prepend=timestamps[0])
    df['iat'] = inter_arrival_times
    return df

def load_dataset(pcap_dir):
    all_data = []
    for file in tqdm(os.listdir(pcap_dir)):
        if file.endswith('.pcap') or file.endswith('.pcapng'):
            file_path = os.path.join(pcap_dir, file)
            df = extract_features_scapy(file_path)
            all_data.append(df)
    return pd.concat(all_data, ignore_index=True)

def train_isolation_forest(data):
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(data)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(X_scaled)
    return model, scaler

def main(pcap_directory):
    print(f"Loading PCAP files from: {pcap_directory}")
    df = load_dataset(pcap_directory)
    print("Feature extraction complete. Total packets:", len(df))

    model, scaler = train_isolation_forest(df)

    scores = model.decision_function(scaler.transform(df))
    predictions = model.predict(scaler.transform(df))

    df['anomaly_score'] = scores
    df['is_anomaly'] = predictions

   # Report summary
    num_anomalies = (df['is_anomaly'] == -1).sum()
    percent_anomalies = (num_anomalies / len(df)) * 100
    print(f"Detected {num_anomalies} anomalies ({percent_anomalies:.2f}% of samples)")

    output_path = os.path.join(output_directory, "detection_results.csv")
    df.to_csv(output_path, index=False)
    print("Results saved to detection_results.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run network anomaly detection on PCAP files.")
    parser.add_argument("pcap_directory", help="Path to directory containing PCAP files")
    parser.add_argument("output_directory", nargs="?", default=".", help="Optional output directory")
    args = parser.parse_args()
    main(pcap_directory)
