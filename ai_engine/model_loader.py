# ==========================================================
# GuardianX AI Model Loader
# ==========================================================

import os
import joblib



# ==========================================================
# Model Path
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)


MODEL_PATH = os.path.join(
    BASE_DIR,
    "threat_model.pkl"
)



# ==========================================================
# Load AI Model
# ==========================================================

def load_model():

    """
    Loads trained AI model if available.
    """

    if os.path.exists(MODEL_PATH):

        model = joblib.load(
            MODEL_PATH
        )

        return model


    return None



# ==========================================================
# Save AI Model
# ==========================================================

def save_model(model):

    """
    Saves trained AI model.
    """

    joblib.dump(
        model,
        MODEL_PATH
    )



# ==========================================================
# Model Status
# ==========================================================

def model_status():

    if os.path.exists(MODEL_PATH):

        return {
            "status": "ACTIVE",
            "message": "GuardianX AI model loaded successfully"
        }


    return {
        "status": "RULE_ENGINE",
        "message": "Using intelligent threat analysis rules"
    }