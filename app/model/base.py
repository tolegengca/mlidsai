from abc import ABCMeta, abstractmethod
from typing import ClassVar, Dict, List, Set
from app.compact import CSE_CIC_IDS_FEATURES


class AbstractModel(metaclass=ABCMeta):
    """
    Abstract base class for anomaly detection models.

    Requires:
    - Declared model name.
    - Declared list of required features from CSE_CIC_IDS_FEATURES.
    - Declared supported labels in {label_name: is_anomaly} format.

    Tracks all subclasses and validates model configuration.
    """

    _registry: ClassVar[Set[str]] = set()
    name: ClassVar[str]
    features: ClassVar[List[str]]
    labels: ClassVar[Dict[str, bool]]

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if not hasattr(cls, "name") or not isinstance(cls.name, str):
            raise ValueError(f"{cls.__name__} must define a valid `name`.")
        if cls.name in AbstractModel._registry:
            raise ValueError(f"Duplicate model name: {cls.name}")
        AbstractModel._registry.add(cls.name)

        if not hasattr(cls, "features") or not isinstance(cls.features, list):
            raise ValueError(f"{cls.__name__} must define `features` as a list.")
        invalid = [f for f in cls.features if f not in CSE_CIC_IDS_FEATURES]
        if invalid:
            raise ValueError(f"{cls.__name__} has invalid features: {invalid}")

        if not hasattr(cls, "labels") or not isinstance(cls.labels, dict):
            raise ValueError(f"{cls.__name__} must define `labels` as a dict.")
        for label, is_anomaly in cls.labels.items():
            if not isinstance(label, str) or not isinstance(is_anomaly, bool):
                raise ValueError(
                    f"{cls.__name__} `labels` must be in {{str: bool}} format."
                )

    @abstractmethod
    def predict(self, features: Dict[str, float]) -> str:
        pass

    @classmethod
    def features_to_list(cls, features: Dict[str, float]) -> List[float]:
        return [features[f] for f in cls.features]

    @classmethod
    def is_anomaly(cls, prediction: str) -> bool:
        return cls.labels.get(prediction, False)
