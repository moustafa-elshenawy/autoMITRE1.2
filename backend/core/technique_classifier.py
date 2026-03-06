import os
import pickle
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

class TechniqueClassifier:
    """
    ML-based classifier trained on the MITRE TRAM (CTI) dataset.
    Takes raw threat intelligence text and predicts the highest probability
    MITRE ATT&CK techniques.
    """
    def __init__(self):
        self.model = None
        self._load_model()
        
    def _load_model(self):
        model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'saved', 'tram_technique_clf.pkl')
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info("Loaded TRAM ML Technique Classifier successfully.")
            except Exception as e:
                logger.error(f"Failed to load TRAM ML Classifier: {e}")
        else:
            logger.warning(f"TRAM ML Classifier not found at {model_path}. Run training script first.")
            
    def predict_techniques(self, text: str, top_k: int = 5, threshold: float = 0.15) -> List[Tuple[str, float]]:
        """
        Predicts MITRE ATT&CK techniques for a given text.
        Returns a list of (technique_id, confidence) tuples.
        """
        if not self.model or not text.strip():
            return []
            
        try:
            # Get probability distribution across all classes
            probas = self.model.predict_proba([text])[0]
            classes = self.model.classes_
            
            # Combine classes and probabilities, sort descending
            predictions = list(zip(classes, probas))
            predictions.sort(key=lambda x: x[1], reverse=True)
            
            # Filter by threshold and take top K
            results = []
            for tech_id, conf in predictions[:top_k]:
                if conf >= threshold and tech_id.upper() != 'NONE':
                    results.append((tech_id, float(conf)))
            return results
            
        except Exception as e:
            logger.error(f"Error predicting techniques: {e}")
            return []

# Singleton instance
classifier = TechniqueClassifier()

def predict(text: str) -> List[Tuple[str, float]]:
    """Helper method to use the singleton."""
    return classifier.predict_techniques(text)
