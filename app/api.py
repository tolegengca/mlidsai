from fastapi import FastAPI, Response
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

from app.compact import convert_cicflowmeter_to_cse_cic_ids
from app.predict import Predictor

app = FastAPI()
predictor = Predictor()

ALL_ANOMALY_TYPES = {
    k
    for model in predictor.models.values()
    for k, v in getattr(model, "labels", {}).items()
    if v
}

# Prometheus metrics
total_bytes = Counter("mlidsai_total_bytes_total", "Total bytes processed")
total_packets = Counter("mlidsai_total_packets_total", "Total packets processed")
total_sessions = Counter("mlidsai_total_sessions_total", "Total new sessions detected")
anomaly_sessions = Counter(
    "mlidsai_anomaly_sessions_total", "Total anomaly sessions detected", ["type"]
)
anomaly_type_bytes = Counter(
    "mlidsai_anomaly_type_bytes_total", "Total bytes per anomaly type", ["type"]
)
anomaly_type_packets = Counter(
    "mlidsai_anomaly_type_packets_total", "Packets per anomaly type", ["type"]
)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
async def get_root():
    return {"message": "POST /predict"}


@app.post("/predict")
async def post_predict(record: dict) -> dict[str, bool]:
    record = convert_cicflowmeter_to_cse_cic_ids(record)
    prediction = predictor.predict(record)
    print("PREDICTION:", prediction)

    # Update metrics
    # Estimate bytes and packets from record (if available)
    fwd_bytes = int(record.get("TotLen Fwd Pkts", 0))
    bwd_bytes = int(record.get("TotLen Bwd Pkts", 0))
    bytes_count = fwd_bytes + bwd_bytes
    fwd_pkts = int(record.get("Tot Fwd Pkts", 0))
    bwd_pkts = int(record.get("Tot Bwd Pkts", 0))
    packets_count = fwd_pkts + bwd_pkts
    total_bytes.inc(bytes_count)
    total_packets.inc(packets_count)
    total_sessions.inc()

    # Always export all anomaly types, set to 0 if not detected
    detected_types = set(prediction.keys())
    for anomaly_type in ALL_ANOMALY_TYPES:
        if anomaly_type in detected_types:
            anomaly_sessions.labels(type=anomaly_type).inc()
            anomaly_type_bytes.labels(type=anomaly_type).inc(bytes_count)
            anomaly_type_packets.labels(type=anomaly_type).inc(packets_count)
        else:
            # Touch the metric to ensure it appears in Prometheus, but do not increment
            anomaly_sessions.labels(type=anomaly_type)
            anomaly_type_bytes.labels(type=anomaly_type)
            anomaly_type_packets.labels(type=anomaly_type)

    return prediction
