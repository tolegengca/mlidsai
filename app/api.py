from pprint import pprint

from fastapi import FastAPI

from app.compact import convert_cicflowmeter_to_cse_cic_ids
from app.predict import Predictor

app = FastAPI()
predictor = Predictor()


@app.get("/")
async def get_root():
    return {"message": "POST /predict"}


@app.post("/predict")
async def post_predict(record: dict) -> dict[str, bool]:
    record = convert_cicflowmeter_to_cse_cic_ids(record)
    prediction = predictor.predict(record)
    pprint(prediction)
    return prediction
