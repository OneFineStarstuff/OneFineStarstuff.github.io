# pylint: disable=missing-docstring, no-member, import-outside-toplevel
# pylint: disable=unused-import, wrong-import-order, no-name-in-module
# pylint: disable=redefined-outer-name, protected-access, line-too-long
# pylint: disable=duplicate-code, assignment-from-none, wrong-import-position

import unittest

from fastapi.testclient import TestClient

from main import EnhancedAGIPipeline, app

class TestMain(unittest.TestCase):
    """HTTP tests for the FastAPI application."""

    def setUp(self):
        """Initialize the test client and pipeline fixture."""
        self.client = TestClient(app)
        self.pipeline = EnhancedAGIPipeline()
        self.headers = {"Authorization": "Bearer DUMMY"}

    def test_process_nlp(self):
        """Verify the text-processing endpoint returns a response."""
        response = self.client.post(
            "/process-nlp/", json={"text": "Hello world"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_process_cv_detection(self):
        """Verify image upload returns object-detection results."""
        # Create a dummy image
        import io

        from PIL import Image

        img = Image.new("RGB", (100, 100), color="red")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format="JPEG")
        img_byte_arr.seek(0)

        response = self.client.post(
            "/process-cv-detection/",
            files={"file": ("test_image.jpg", img_byte_arr, "image/jpeg")},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("detections", response.json())

    def test_speech_to_text(self):
        """Verify uploaded audio is accepted by the speech endpoint."""
        # Create a dummy wav file
        import io
        import wave

        audio_io = io.BytesIO()
        with wave.open(audio_io, "wb") as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(44100)
            wav_file.writeframes(b"\x00\x00" * 1000)
        audio_io.seek(0)

        response = self.client.post(
            "/speech-to-text/",
            files={"file": ("test_audio.wav", audio_io, "audio/wav")},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_text_to_speech(self):
        """Verify the speech synthesis endpoint returns completion."""
        response = self.client.post(
            "/text-to-speech/", json={"text": "Hello world"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"response": "Speech synthesis complete."})


if __name__ == "__main__":
    unittest.main()
