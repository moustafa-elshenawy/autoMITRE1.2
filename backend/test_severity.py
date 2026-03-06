import os
import json
import logging
import numpy as np
import xgboost as xgb
from core.ml_engine import EnsembleMLEngine
import re

logging.basicConfig(level=logging.INFO)

engine = EnsembleMLEngine()

text1 = "An attacker sent a spearphishing email with a malicious attachment. Upon opening, it executed a script that dumped OS credentials and attempted to establish external command and control."
text2 = "An attacker sent a spearphishing email with a malicious attachment. Upon opening, it executed a script that dumped OS credentials and attempted to establish external command and control. and then they encrypted the database"

f1 = engine._extract_features(text1, [], 6.5)
f2 = engine._extract_features(text2, [], 6.5)

print("Features 1:", f1)
print("Features 2:", f2)

if engine.xgb_model:
    s1 = engine.xgb_model.predict(f1)[0]
    s2 = engine.xgb_model.predict(f2)[0]
    print("XGB Score 1:", s1)
    print("XGB Score 2:", s2)

if engine.text_classifier.model:
    t1 = engine.text_classifier.predict(text1)
    t2 = engine.text_classifier.predict(text2)
    print("Text Score 1:", t1)
    print("Text Score 2:", t2)

print("Evaluate 1:", engine.evaluate_threat({'normalized_text': text1}, 6.5))
print("Evaluate 2:", engine.evaluate_threat({'normalized_text': text2}, 6.5))
