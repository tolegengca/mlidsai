import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from xgboost import XGBClassifier

from app.model.base import AbstractModel


class XDGBoost(AbstractModel):
    """
    XDGBoost model for anomaly detection.
    Supports 7 labels.
    """

    name = "xdgboost"
    features = [
        "Dst Port",
        "Protocol",
        "TotLen Fwd Pkts",
        "Fwd Pkt Len Std",
        "Bwd Pkt Len Min",
        "Flow Byts/s",
        "Fwd IAT Min",
        "Bwd IAT Tot",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",
        "Fwd PSH Flags",
        "Fwd URG Flags",
        "Fwd Pkts/s",
        "Bwd Pkts/s",
        "Pkt Len Min",
        "Pkt Len Std",
        "Pkt Len Var",
        "FIN Flag Cnt",
        "PSH Flag Cnt",
        "ACK Flag Cnt",
        "URG Flag Cnt",
        "ECE Flag Cnt",
        "Down/Up Ratio",
        "Pkt Size Avg",
        "Subflow Bwd Byts",
        "Init Fwd Win Byts",
        "Init Bwd Win Byts",
        "Fwd Act Data Pkts",
        "Fwd Seg Size Min",
        "Active Std",
        "Active Max",
        "Active Min",
        "Idle Std",
        "Idle Min",
    ]

    label_index = [
        "Benign",
        "Botnet",
        "Brute-force",
        "DDoS attack",
        "DoS attack",
        "Infilteration",
        "Web attack",
    ]
    labels = {
        k: k != "Benign" for k in label_index
    }

    def __init__(self):
        project_root = Path(__file__).parent.parent.parent
        files = project_root / "files" / "xdgboost"
        self.model = XGBClassifier()
        self.model.load_model(files / "xdgboost.json")

        with open(files / "scaler_params.json") as f:
            loaded_params = json.load(f)

        self.scaler = MinMaxScaler(feature_range=tuple(loaded_params["feature_range"]))
        self.scaler.min_ = np.array(loaded_params["min_"])
        self.scaler.scale_ = np.array(loaded_params["scale_"])
        self.scaler.data_min_ = np.array(loaded_params["data_min_"])
        self.scaler.data_max_ = np.array(loaded_params["data_max_"])
        self.scaler.data_range_ = np.array(loaded_params["data_range_"])
        self.scaler.n_features_in_ = loaded_params["n_features_in_"]
        self.scaler.feature_names_in_ = np.array(self.features)

    def predict(self, features: dict) -> str:
        # Ensure required fields are present
        features = features.copy()

        # Extract features in the correct order
        try:
            feature_vector = [features[f] for f in self.features]
        except KeyError as e:
            raise ValueError(f"Missing feature for prediction: {e}")

        # Reshape for sklearn (1 sample)
        feature_df = pd.DataFrame([feature_vector], columns=self.features)

        # Scale and transform
        scaled = self.scaler.transform(feature_df)

        # Predict
        pred = self.model.predict(scaled)[0]
        return self.label_index[pred]
