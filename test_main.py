# pylint: disable=missing-docstring, no-member, import-outside-toplevel, unused-import, wrong-import-order,
# pylint: disable=no-name-in-module, redefined-outer-name, protected-access, line-too-long, duplicate-code,
# pylint: disable=assignment-from-none, wrong-import-position
import importlib.util
import io
import sys
import unittest
import wave
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

from fastapi.testclient import TestClient
from PIL import Image


class StubNLPModule:
    def generate_text(self, prompt: str) -> str:
        return f"stub response for: {prompt}"


class StubCVModule:
    def detect_objects(self, image: Image.Image) -> str:
        return "[]"


class StubSpeechProcessor:
    def speech_to_text(self, audio_file: object) -> str:
        return "stub transcription"

    def text_to_speech(self, text: str) -> None:
        return None


def _stub_module(
    module_name: str, symbol_name: str, implementation: type[object]
) -> ModuleType:
    module = ModuleType(module_name)
    setattr(module, symbol_name, implementation)
    return module


TEST_MODULES = {
    "nlp_module": _stub_module("nlp_module", "NLPModule", StubNLPModule),
    "cv_module": _stub_module("cv_module", "CVModule", StubCVModule),
    "speech_processor": _stub_module(
        "speech_processor", "SpeechProcessor", StubSpeechProcessor
    ),
}

# Load the API with test doubles so collection does not download or initialize
# external NLP, vision, or speech models.
with mock.patch.dict(sys.modules, TEST_MODULES):
    spec = importlib.util.spec_from_file_location(
        "gien_main_under_test", Path(__file__).with_name("main.py")
    )
    assert spec is not None and spec.loader is not None
    main: Any = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main)


class TestMain(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(main.app)
        self.pipeline = main.EnhancedAGIPipeline()
        self.headers = {"Authorization": f"Bearer {main.VALID_API_KEY}"}

    def test_process_nlp(self) -> None:
        response = self.client.post(
            "/process-nlp/", json={"text": "Hello world"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["response"], "stub response for: Hello world")

    def test_process_cv_detection(self) -> None:
        image_buffer = io.BytesIO()
        Image.new("RGB", (100, 100), color="red").save(image_buffer, format="JPEG")
        image_buffer.seek(0)

        response = self.client.post(
            "/process-cv-detection/",
            files={"file": ("test_image.jpg", image_buffer, "image/jpeg")},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["detections"], "[]")

    def test_speech_to_text(self) -> None:
        audio_buffer = io.BytesIO()
        with wave.open(audio_buffer, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(44100)
            wav_file.writeframes(b"\x00\x00" * 1000)
        audio_buffer.seek(0)

        response = self.client.post(
            "/speech-to-text/",
            files={"file": ("test_audio.wav", audio_buffer, "audio/wav")},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["response"], "stub transcription")

    def test_text_to_speech(self) -> None:
        response = self.client.post(
            "/text-to-speech/", json={"text": "Hello world"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"response": "Speech synthesis complete."})


if __name__ == "__main__":
    unittest.main()
