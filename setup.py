from setuptools import setup, find_packages

setup(
    name="agi_pipeline",
    version="1.0.1",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
        "torch",
        "transformers",
        "Pillow",
        "whisper",
        "ultralytics",
        "pyttsx3",
        "loguru",
        "nest_asyncio"
    ],
)
