import time
import random
import requests
import pandas as pd
from pathlib import Path

API_URL = "http://localhost:8000/predict_cse_cic_ids"
CSV_PATH = Path(__file__).parent / "csv_1k.csv"

# Read CSV and get labels
print("Loading data...")
df = pd.read_csv(CSV_PATH)
labels = sorted(df['Label'].unique())

print("Available Labels:")
for idx, label in enumerate(labels):
    print(f"{idx + 1}. {label}")

label_input = input("Select labels to use (comma separated indices, blank for all): ")
if label_input.strip():
    selected_indices = [int(i) - 1 for i in label_input.split(",") if i.strip().isdigit() and 0 < int(i) <= len(labels)]
    selected_labels = [labels[i] for i in selected_indices]
else:
    selected_labels = labels

print(f"Selected labels: {selected_labels}")

try:
    session_rate = int(input("Sessions per second (default 100): ") or "100")
except ValueError:
    session_rate = 100

print(f"Session rate: {session_rate} per second")

# Filter dataframe by selected labels
filtered_df = df[df['Label'].isin(selected_labels)]

if filtered_df.empty:
    print("No sessions found for selected labels.")
    exit(1)

# Remove label column for posting
feature_cols = [col for col in filtered_df.columns if col != 'Label']

# Main simulation loop
def simulate():
    while True:
        # Calculate how many sessions to send this tick (10 ticks per second)
        base = session_rate // 10
        remainder = session_rate % 10
        for tick in range(10):
            # Randomize count +-10%
            count = base + (1 if tick < remainder else 0)
            count = int(count * random.uniform(0.9, 1.1))
            # Randomly select sessions
            batch = filtered_df.sample(n=min(count, len(filtered_df)), replace=True)
            # Shuffle
            batch = batch.sample(frac=1)
            # Post each session
            for _, row in batch.iterrows():
                data = row[feature_cols].to_dict()
                try:
                    requests.post(API_URL, json=data, timeout=1)
                except Exception as e:
                    print(f"Post failed: {e}")
            time.sleep(0.1)

if __name__ == "__main__":
    print("Starting simulation. Press Ctrl+C to stop.")
    try:
        simulate()
    except KeyboardInterrupt:
        print("\nSimulation stopped.")
