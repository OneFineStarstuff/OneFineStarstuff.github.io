"""
Main entry point for the Enhanced AGI Pipeline API.
"""

import os
from io import BytesIO
from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from PIL import Image
from loguru import logger

from nlp_module import NLPModule
from cv_module import CVModule
from speech_processor import SpeechProcessor

# API Key from environment or default
VALID_API_KEY = os.getenv("AGI_API_KEY", "YvZz9Hni0hWJPh_UWW4dQYf9rhIe9nNYcC5ZQTTZz0Q")

security = HTTPBearer()


class EnhancedAGIPipeline:
    """
    A wrapper class that integrates NLP, CV, and Speech modules.
    """

    def __init__(self):
        """
        Initializes all pipeline modules.
        """
        self.nlp = NLPModule()
        self.cv = CVModule()
        self.speech = SpeechProcessor()

    def process_nlp(self, prompt: str) -> str:
        """
        Processes text using the NLP module.
        """
        return self.nlp.generate_text(prompt)

    def process_cv(self, image: Image.Image) -> str:
        """
        Processes an image using the CV module.
        """
        return self.cv.detect_objects(image)

    def process_stt(self, file: UploadFile) -> str:
        """
        Processes audio using the STT module.
        """
        return self.speech.speech_to_text(file)

    def process_tts(self, text: str) -> None:
        """
        Processes text using the TTS module.
        """
        self.speech.text_to_speech(text)


app = FastAPI()
agi = EnhancedAGIPipeline()


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Verifies the Bearer token in the Authorization header.
    """
    if credentials.credentials != VALID_API_KEY:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.post("/process-nlp/", dependencies=[Depends(verify_token)])
async def process_nlp(data: dict):
    """
    Endpoint for text generation.
    """
    try:
        prompt = data.get("text", "")
        return {"response": agi.process_nlp(prompt)}
    except Exception as e:
        logger.error(f"NLP Error: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/process-cv-detection/", dependencies=[Depends(verify_token)])
async def process_cv_detection(file: UploadFile = File(...)):
    """
    Endpoint for object detection in images.
    """
    try:
        image_data = await file.read()
        image = Image.open(BytesIO(image_data))
        return {"detections": agi.process_cv(image)}
    except Exception as e:
        logger.error(f"CV Error: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/speech-to-text/", dependencies=[Depends(verify_token)])
async def speech_to_text(file: UploadFile = File(...)):
    """
    Endpoint for Speech-to-Text conversion.
    """
    try:
        return {"response": agi.process_stt(file)}
    except Exception as e:
        logger.error(f"STT Error: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


@app.post("/text-to-speech/", dependencies=[Depends(verify_token)])
async def text_to_speech(data: dict):
    """
    Endpoint for Text-to-Speech conversion.
    """
    try:
        text = data.get("text", "")
        agi.process_tts(text)
        return {"response": "Speech synthesis complete."}
    except Exception as e:
        logger.error(f"TTS Error: {e}")
        raise HTTPException(status_code=500, detail=str(e)) from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
