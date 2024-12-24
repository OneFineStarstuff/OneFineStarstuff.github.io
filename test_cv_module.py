import unittest
from PIL import Image
from cv_module import CVModule

class TestCVModule(unittest.TestCase):
    def setUp(self):
        self.cv = CVModule()

    def test_detect_objects(self):
        # Create a dummy image for testing
        image = Image.new('RGB', (100, 100), color = 'white')
        result = self.cv.detect_objects(image)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)

    def test_detect_objects_invalid_image(self):
        with self.assertRaises(ValueError):
            self.cv.detect_objects(None)

if __name__ == '__main__':
    unittest.main()
