from app.model.base import AbstractModel


class StaticModel(AbstractModel):
    """
    Static model for testing purposes.
    Always returns the same label.
    """

    name = "static"
    features = ["Protocol"]
    labels = {"normal": False, "anomaly": True}

    def __init__(self, label: str):
        if label not in self.labels:
            raise ValueError(f"Invalid label: {label}")
        self.label = label

    def predict(self, features: dict) -> str:
        return self.label
