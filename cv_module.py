import torch
from ultralytics import YOLO
from PIL import Image
from loguru import logger

class CVModule:
    def __init__(self):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = YOLO('yolov8n.pt').to(self.device)
        logger.info("CV model loaded successfully.")

    def detect_objects(self, image: Image.Image) -> str:
        if image is None:
            raise ValueError("Image cannot be None.")
        logger.debug("Detecting objects in the image.")
        results = self.model(image)
        # In YOLOv8, results is a list. Each result object has a to_json method.
        return results[0].to_json()
