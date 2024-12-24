# AGI Pipeline

## Overview

A comprehensive AGI pipeline integrating NLP, Computer Vision, and Speech Processing using pre-trained models.

## Features
- Text generation with T5
- Object detection with YOLO
- Speech-to-text with Whisper
- Text-to-speech with Pyttsx3

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/yourusername/agi-pipeline.git
    ```
    
2. **Navigate to the project directory**:
    ```bash
    cd agi-pipeline
    ```
    
3. **Create and activate a virtual environment**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
    
4. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. **Run the FastAPI application**:
    ```bash
    uvicorn main:app --reload
    ```
    
2. **Access the API** at `http://127.0.0.1:8000`.

## Using Docker

1. **Build the Docker image**:
    ```bash
    docker build -t agi-pipeline:1.0.1 .
    ```

2. **Run the Docker container**:
    ```bash
    docker run -p 8000:8000 agi-pipeline:1.0.1
    ```

## Contributing

Feel free to open issues or submit pull requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.
