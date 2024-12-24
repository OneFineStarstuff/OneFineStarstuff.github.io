# === Imports ===
import os
import asyncio
import time
from typing import List
import torch
from transformers import T5Tokenizer, T5ForConditionalGeneration
from PIL import Image
from fastapi import FastAPI, UploadFile, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, SecretStr
import whisper
from ultralytics import YOLO
import pyttsx3
from loguru import logger
import io
import nest_asyncio
import uvicorn

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

# === NLP Module (T5 Transformer) ===
class NLPModule:
    def __init__(self):
        model_name = "google/flan-t5-small"
        self.tokenizer = T5Tokenizer.from_pretrained(model_name)
        self.model = T5ForConditionalGeneration.from_pretrained(model_name)
        logger.info("NLP model loaded successfully.")

    def generate_text(self, prompt: str) -> str:
        if not prompt.strip():
            raise ValueError("Prompt cannot be empty.")
        logger.debug(f"Generating text for prompt: {prompt}")
        inputs = self.tokenizer(prompt, return_tensors="pt")
        outputs = self.model.generate(inputs["input_ids"], max_length=100)
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        logger.info(f"Generated response: {response}")
        return response

# === CV Module (YOLOv8 for Object Detection) ===
class CVModule:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = YOLO('yolov8n.pt').to(self.device)
        logger.info("CV model loaded successfully.")

    def detect_objects(self, image: Image.Image) -> str:
        logger.debug("Detecting objects in the image.")
        results = self.model(image)
        return results.pandas().xyxy[0].to_json()

# === Speech Processor (Whisper for Speech-to-Text, PyTTSX3 for Text-to-Speech) ===
class SpeechProcessor:
    def __init__(self):
        self.whisper_model = whisper.load_model("base")
        self.tts = pyttsx3.init()
        logger.info("Speech processor initialized successfully.")

    def speech_to_text(self, audio_file: UploadFile) -> str:
        with audio_file.file as audio_data:
            result = self.whisper_model.transcribe(audio_data)
            return result['text']

    def text_to_speech(self, text: str) -> None:
        if not text.strip():
            raise ValueError("Text cannot be empty.")
        self.tts.say(text)
        self.tts.runAndWait()

    def __del__(self):
        self.tts.stop()

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
