# from app.model import StaticModel
from app.model import IsolationForest, RandomForest


class Predictor:
    def __init__(self):
        models = [
            # StaticModel("normal"),
            IsolationForest(),
            RandomForest(),
        ]
        self.models = {model.name: model for model in models}

    def predict(self, record: dict) -> dict[str, bool]:
        """
        Predict anomalies in a given record using the loaded models.
        Returns a dictionary with prediction label and whether it is an anomaly.
        """
        predictions = dict()

        for model in self.models.values():
            if prediction := model.predict(model.filter_features(record)):
                predictions[prediction] = model.is_anomaly(prediction)

        return predictions
