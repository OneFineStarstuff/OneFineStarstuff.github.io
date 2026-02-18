import unittest
import os
from main import app, EnhancedAGIPipeline
from fastapi.testclient import TestClient

class TestMain(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.pipeline = EnhancedAGIPipeline()
        self.headers = {"Authorization": "Bearer YvZz9Hni0hWJPh_UWW4dQYf9rhIe9nNYcC5ZQTTZz0Q"}

    def test_process_nlp(self):
        response = self.client.post("/process-nlp/", json={"text": "Hello world"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_process_cv_detection(self):
        # Create a dummy image
        from PIL import Image
        import io
        img = Image.new('RGB', (100, 100), color = 'red')
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='JPEG')
        img_byte_arr.seek(0)

        response = self.client.post("/process-cv-detection/", files={"file": ("test_image.jpg", img_byte_arr, "image/jpeg")}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("detections", response.json())

    def test_speech_to_text(self):
        # Create a dummy wav file
        import wave
        import io
        audio_io = io.BytesIO()
        with wave.open(audio_io, 'wb') as wav_file:
            wav_file.setnchannels(1)
            wav_file.setsampwidth(2)
            wav_file.setframerate(44100)
            wav_file.writeframes(b'\x00\x00' * 1000)
        audio_io.seek(0)

        response = self.client.post("/speech-to-text/", files={"file": ("test_audio.wav", audio_io, "audio/wav")}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn("response", response.json())

    def test_text_to_speech(self):
        response = self.client.post("/text-to-speech/", json={"text": "Hello world"}, headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"response": "Speech synthesis complete."})

if __name__ == '__main__':
    unittest.main()
