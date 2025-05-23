from app.model import StaticModel


class Predictor:
    def __init__(self):
        models = [
            StaticModel("normal"),
        ]
        self.models = {model.name: model for model in models}

    def predict(self, record: dict) -> set:
        predictions = set()

        for model in self.models.values():
            prediction = model.predict(record)
            if prediction and model.is_anomaly(prediction):
                predictions.add(prediction)

        return predictions
