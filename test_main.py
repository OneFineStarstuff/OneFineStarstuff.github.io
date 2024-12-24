import unittest
from main import app, EnhancedAGIPipeline
from fastapi.testclient import TestClient

class TestMain(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.pipeline = EnhancedAGIPipeline()

    def test_process_nlp(self):
        response = self.client.post("/process-nlp/", json={"text": "Hello world"})
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_process_cv_detection(self):
        with open("test_image.jpg", "rb") as image:
            response = self.client.post("/process-cv-detection/", files={"file": ("filename", image, "image/jpeg")})
        self.assertEqual(response.status_code, 200)
        self.assertIn("detections", response.json())

    def test_speech_to_text(self):
        with open("test_audio.wav", "rb") as audio:
            response = self.client.post("/speech-to-text/", files={"file": ("filename", audio, "audio/wav")})
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_text_to_speech(self):
        response = self.client.post("/text-to-speech/", json={"text": "Hello world"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"response": "Speech synthesis complete."})

if __name__ == '__main__':
    unittest.main()
