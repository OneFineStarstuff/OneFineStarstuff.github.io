# pylint: disable=missing-docstring, no-member, import-outside-toplevel, unused-import, wrong-import-order, no-name-in-module, redefined-outer-name, protected-access, line-too-long, duplicate-code , assignment-from-none, wrong-import-position
import io
import os
import unittest
import wave
from io import BytesIO

from fastapi import UploadFile

from speech_processor import SpeechProcessor


class TestSpeechProcessor(unittest.TestCase):
    def setUp(self):
        self.speech_processor = SpeechProcessor()

    def test_speech_to_text(self):
        # Create a valid dummy wav file for testing
        audio_io = io.BytesIO()
        with wave.open(audio_io, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(44100)
            wav_file.writeframes(b"\x00\x00" * 1000)
        audio_io.seek(0)

        audio_file = UploadFile(filename="test.wav", file=audio_io)
        result = self.speech_processor.speech_to_text(audio_file)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_text_to_speech(self):
        text = "Hello world!"
        result = self.speech_processor.text_to_speech(text)
        self.assertIsNone(result)  # Text-to-speech returns None

    def test_text_to_speech_empty_text(self):
        with self.assertRaises(ValueError):
            self.speech_processor.text_to_speech("")


if __name__ == "__main__":
    unittest.main()
