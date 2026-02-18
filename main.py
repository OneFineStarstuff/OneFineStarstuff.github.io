# === Imports ===
import os
import asyncio
from typing import List
from PIL import Image
from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, SecretStr
from loguru import logger
import io
import nest_asyncio
import uvicorn

# Import modules
from nlp_module import NLPModule
from cv_module import CVModule
from speech_processor import SpeechProcessor

# === Logging Setup ===
logger.add("pipeline_{time}.log", rotation="1 MB", level="DEBUG", enqueue=True, backtrace=True, diagnose=True)
logger.info("Application startup")

# === Security Enhancement: Environment Variable for Secure Token ===
SECURE_TOKEN = SecretStr(os.getenv("SECURE_TOKEN", "YvZz9Hni0hWJPh_UWW4dQYf9rhIe9nNYcC5ZQTTZz0Q"))

# === OAuth2PasswordBearer for Authentication ===
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# === Authentication Function ===
def authenticate_user(token: str = Depends(oauth2_scheme)):
    if token != SECURE_TOKEN.get_secret_value():
        logger.warning("Authentication failed.")
        raise HTTPException(status_code=401, detail="Invalid token")

# === Request and Response Models (Pydantic) ===
class TextRequest(BaseModel):
    text: str

class TextResponse(BaseModel):
    response: str

# === Enhanced AGI Pipeline ===
class EnhancedAGIPipeline:
    def __init__(self):
        self.nlp = NLPModule()
        self.cv = CVModule()
        self.speech_processor = SpeechProcessor()

    async def process_nlp(self, text: str) -> str:
        return await asyncio.to_thread(self.nlp.generate_text, text)

    async def process_cv(self, image: Image.Image) -> str:
        return await asyncio.to_thread(self.cv.detect_objects, image)

    async def process_speech_to_text(self, audio_file: UploadFile) -> str:
        return await asyncio.to_thread(self.speech_processor.speech_to_text, audio_file)

    async def process_text_to_speech(self, text: str) -> None:
        await asyncio.to_thread(self.speech_processor.text_to_speech, text)

# === FastAPI Application ===
app = FastAPI()

pipeline = EnhancedAGIPipeline()

# === Endpoints ===
@app.post("/process-nlp/", response_model=TextResponse, dependencies=[Depends(authenticate_user)])
async def process_nlp(request: TextRequest):
    response = await pipeline.process_nlp(request.text)
    return {"response": response}

@app.post("/process-cv-detection/", dependencies=[Depends(authenticate_user)])
async def process_cv_detection(file: UploadFile):
    image = Image.open(io.BytesIO(await file.read()))
    response = await pipeline.process_cv(image)
    return {"detections": response}

@app.post("/batch-cv-detection/", dependencies=[Depends(authenticate_user)])
async def batch_cv_detection(files: List[UploadFile]):
    responses = []
    for file in files:
        image = Image.open(io.BytesIO(await file.read()))
        response = await pipeline.process_cv(image)
        responses.append(response)
    return {"batch_detections": responses}

@app.post("/speech-to-text/", response_model=TextResponse, dependencies=[Depends(authenticate_user)])
async def speech_to_text(file: UploadFile):
    response = await pipeline.process_speech_to_text(file)
    return {"response": response}

@app.post("/text-to-speech/", dependencies=[Depends(authenticate_user)])
async def text_to_speech(request: TextRequest):
    await pipeline.process_text_to_speech(request.text)
    return {"response": "Speech synthesis complete."}

# === Run the Application with HTTPS (uvicorn) ===
if __name__ == "__main__":
    nest_asyncio.apply()
    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)
    asyncio.run(server.serve())
