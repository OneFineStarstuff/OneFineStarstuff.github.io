import whisper
import pyttsx3
import tempfile
import os
from fastapi import UploadFile
from loguru import logger

class SpeechProcessor:
    def __init__(self):
        self.whisper_model = whisper.load_model("base")
        try:
            self.tts = pyttsx3.init()
            logger.info("Speech processor (TTS) initialized successfully.")
        except Exception as e:
            self.tts = None
            logger.error(f"Failed to initialize TTS engine: {e}")
        logger.info("Whisper model loaded successfully.")

    def speech_to_text(self, audio_file: UploadFile) -> str:
        logger.debug(f"Transcribing audio file: {audio_file.filename}")
        # Save UploadFile to a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(audio_file.filename)[1]) as tmp:
            tmp.write(audio_file.file.read())
            tmp_path = tmp.name

        try:
            result = self.whisper_model.transcribe(tmp_path)
            return result['text']
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def text_to_speech(self, text: str) -> None:
        if not text.strip():
            raise ValueError("Text cannot be empty.")

        if self.tts is None:
            logger.warning("TTS engine not available. Skipping speech synthesis.")
            return

        try:
            logger.debug(f"Synthesizing text: {text}")
            self.tts.say(text)
            self.tts.runAndWait()
        except Exception as e:
            logger.error(f"TTS synthesis failed: {e}")

    def __del__(self):
        if hasattr(self, 'tts') and self.tts:
            try:
                self.tts.stop()
            except:
                pass
