from pathlib import Path

import joblib
import pandas as pd

from app.model.base import AbstractModel


class IsolationForest(AbstractModel):
    """
    Isolation Forest model for anomaly detection.
    Supports only Normal and Anomaly labels.
    """

    name = "isolation_forest"
    # Uses all available features from the CSE-CIC-IDS dataset
    # Extra Src IP, Src Port and Dst IP are required for the model to work
    # But they are not present in the CSE-CIC-IDS dataset, so 0 are used instead
    features = [
        "Dst Port",
        "Protocol",
        "Flow Duration",
        "Tot Fwd Pkts",
        "Tot Bwd Pkts",
        "TotLen Fwd Pkts",
        "TotLen Bwd Pkts",
        "Fwd Pkt Len Max",
        "Fwd Pkt Len Min",
        "Fwd Pkt Len Mean",
        "Fwd Pkt Len Std",
        "Bwd Pkt Len Max",
        "Bwd Pkt Len Min",
        "Bwd Pkt Len Mean",
        "Bwd Pkt Len Std",
        "Flow Byts/s",
        "Flow Pkts/s",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",
        "Fwd IAT Tot",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",
        "Bwd IAT Tot",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Bwd PSH Flags",
        "Fwd URG Flags",
        "Bwd URG Flags",
        "Fwd Header Len",
        "Bwd Header Len",
        "Fwd Pkts/s",
        "Bwd Pkts/s",
        "Pkt Len Min",
        "Pkt Len Max",
        "Pkt Len Mean",
        "Pkt Len Std",
        "Pkt Len Var",
        "FIN Flag Cnt",
        "SYN Flag Cnt",
        "RST Flag Cnt",
        "PSH Flag Cnt",
        "ACK Flag Cnt",
        "URG Flag Cnt",
        "CWE Flag Count",
        "ECE Flag Cnt",
        "Down/Up Ratio",
        "Pkt Size Avg",
        "Fwd Seg Size Avg",
        "Bwd Seg Size Avg",
        "Fwd Byts/b Avg",
        "Fwd Pkts/b Avg",
        "Fwd Blk Rate Avg",
        "Bwd Byts/b Avg",
        "Bwd Pkts/b Avg",
        "Bwd Blk Rate Avg",
        "Subflow Fwd Pkts",
        "Subflow Fwd Byts",
        "Subflow Bwd Pkts",
        "Subflow Bwd Byts",
        "Init Fwd Win Byts",
        "Init Bwd Win Byts",
        "Fwd Act Data Pkts",
        "Fwd Seg Size Min",
        "Active Mean",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Mean",
        "Idle Std",
        "Idle Max",
        "Idle Min",
    ]
    final_features = features + ["Src IP", "Src Port", "Dst IP"]
    labels = {"normal": False, "anomaly": True}

    def __init__(self):
        project_root = Path(__file__).parent.parent.parent
        self.model = joblib.load(
            project_root / "files" / "isolation_forest" / "isolation_forest.joblib"
        )
        self.feature_scaler = joblib.load(
            project_root / "files" / "isolation_forest" / "feature_scaler.joblib"
        )
        self.pca_transformer = joblib.load(
            project_root / "files" / "isolation_forest" / "pca_transformer.joblib"
        )

    def predict(self, features: dict) -> str:
        # Ensure required fields are present
        features = features.copy()
        features["Src IP"] = 0
        features["Src Port"] = 0
        features["Dst IP"] = 0
        features["CWE Flag Count"] = 0

        # Extract features in the correct order
        try:
            feature_vector = [features[f] for f in self.final_features]
        except KeyError as e:
            raise ValueError(f"Missing feature for prediction: {e}")

        # Reshape for sklearn (1 sample)
        feature_df = pd.DataFrame([feature_vector], columns=self.final_features)

        # Scale and transform
        scaled = self.feature_scaler.transform(feature_df)
        pca = self.pca_transformer.transform(scaled)

        # Predict
        pred = self.model.predict(pca)[0]  # -1: anomaly, 1: normal
        return "anomaly" if pred == -1 else "normal"
