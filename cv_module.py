"""
Computer Vision Module for the Enhanced AGI Pipeline.
"""

import torch
from loguru import logger
from PIL import Image
from ultralytics import YOLO


class CVModule:
    """
    A module for Computer Vision tasks using YOLOv8.
    """

    def __init__(self):
        """
        Initializes the YOLOv8 model.
        """
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = YOLO("yolov8n.pt").to(self.device)
        logger.info("CV model loaded successfully.")

    def detect_objects(self, image: Image.Image) -> str:
        """
        Detects objects in the provided image.

        Args:
            image (Image.Image): The input image.

        Returns:
            str: JSON string containing detection results.

        Raises:
            ValueError: If the image is None.
        """
        if image is None:
            raise ValueError("Image cannot be None.")
        logger.debug("Detecting objects in the image.")
        results = self.model(image)
        # In YOLOv8, results is a list. Each result object has a to_json method.
        return results[0].to_json()
