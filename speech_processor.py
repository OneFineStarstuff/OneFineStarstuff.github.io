"""
Speech Processing Module for the Enhanced AGI Pipeline.
"""

import os
import tempfile

import pyttsx3
import whisper
from fastapi import UploadFile
from loguru import logger


class SpeechProcessor:
    """
    A module for Speech-to-Text (STT) and Text-to-Speech (TTS) processing.
    """

    def __init__(self):
        """
        Initializes the Whisper model and the TTS engine.
        """
        self.whisper_model = whisper.load_model("base")
        try:
            self.tts = pyttsx3.init()
            logger.info("Speech processor (TTS) initialized successfully.")
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.tts = None
            logger.error(f"Failed to initialize TTS engine: {e}")
        logger.info("Whisper model loaded successfully.")

    def speech_to_text(self, audio_file: UploadFile) -> str:
        """
        Converts speech from an uploaded audio file to text.

        Args:
            audio_file (UploadFile): The uploaded audio file.

        Returns:
            str: The transcribed text.
        """
        logger.debug(f"Transcribing audio file: {audio_file.filename}")
        # Save UploadFile to a temporary file
        suffix = os.path.splitext(audio_file.filename)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(audio_file.file.read())
            tmp_path = tmp.name

        try:
            result = self.whisper_model.transcribe(tmp_path)
            return result["text"]
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def text_to_speech(self, text: str) -> None:
        """
        Converts text to speech and plays it.

        Args:
            text (str): The text to synthesize.

        Raises:
            ValueError: If the text is empty.
        """
        if not text.strip():
            raise ValueError("Text cannot be empty.")

        if self.tts is None:
            logger.warning("TTS engine not available. Skipping speech synthesis.")
            return

        try:
            logger.debug(f"Synthesizing text: {text}")
            self.tts.say(text)
            self.tts.runAndWait()
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(f"TTS synthesis failed: {e}")

    def __del__(self):
        """
        Cleans up the TTS engine resources.
        """
        if hasattr(self, "tts") and self.tts:
            try:
                self.tts.stop()
            except Exception as e:  # pylint: disable=broad-exception-caught
                # Use logging instead of 'pass' to satisfy Bandit B110
                logger.debug(f"Could not stop TTS engine: {e}")
