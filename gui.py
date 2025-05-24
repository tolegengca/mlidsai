import streamlit as st
import pandas as pd

from app.predict import Predictor
from app.compact import convert_cicflowmeter_to_cse_cic_ids

predictor = Predictor()

st.title("Session Anomaly Detection")

data_file = st.file_uploader("Upload session CSV", type=["csv"])

model_names = predictor.models.keys()
selected_models = st.multiselect(
    "Select models to apply", model_names, default=model_names
)

mandatory_fields = [
    "Timestamp",
    "Protocol",
    "Dst Port",
]

if data_file is not None and selected_models:
    df = pd.read_csv(data_file)
    df = df.apply(convert_cicflowmeter_to_cse_cic_ids, axis=1, result_type="expand")

    display_fields = [f for f in mandatory_fields if f in df.columns]
    results = []
    for idx, row in df.iterrows():
        record = row.to_dict()
        predictions = predictor.predict(record)
        is_anomaly = any(predictions.values())
        results.append(
            {
                "Anomaly": is_anomaly,
                "Labels": ", ".join(predictions.keys()),
            }
        )
    results_df = pd.DataFrame(results)
    display_df = pd.concat([df[display_fields], results_df], axis=1)

    st.dataframe(
        display_df.style.apply(
            # Highlight anomalies in red
            lambda x: [
                "background-color: #E30B5C" if x.get("Anomaly") else "" for _ in x
            ],
            axis=1,
        ),
        use_container_width=True,
    )
else:
    st.info("Please upload a CSV file and select at least one model.")
