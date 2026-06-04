# AGI Pipeline

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Zenodo](https://zenodo.org/badge/DOI/10.5281/zenodo.14504697.svg)](https://doi.org/10.5281/zenodo.14504697)

## Overview

A comprehensive, modular AGI (Artificial General Intelligence) pipeline integrating state-of-the-art NLP, Computer Vision, and Speech Processing capabilities. This framework is designed to facilitate seamless integration and interaction between different AI modules, enabling the development of sophisticated AI applications.

## Features

- **Natural Language Processing (NLP)**: Text generation and summarization using models like T5 and BART.
- **Computer Vision (CV)**: Object detection with YOLOv8 and image classification with ResNet50.
- **Speech Processing**: Speech-to-text with Whisper (STT) and text-to-speech with Pyttsx3 (TTS).
- **Multi-Modal Integration**: Understanding scene context by combining text and image inputs.
- **Reinforcement Learning (RL)**: Training agents using PPO in custom environments.
- **Real-Time Processing**: Handling live video and audio streams for low-latency analysis.

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/OneFineStarstuff/AGI-Pipeline.git
    cd AGI-Pipeline
    ```

2. **Set up a virtual environment**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4. **System Dependencies**:
    Ensure `ffmpeg` and `espeak-ng` are installed for speech processing.

## Usage

### Running the API

1. **Start the FastAPI application**:
    ```bash
    uvicorn main:app --reload
    ```

2. **Access the Interactive Documentation**:
    Open `http://127.0.0.1:8000/docs` in your browser to explore the API endpoints.

### Using Docker

1. **Build the image**:
    ```bash
    docker build -t agi-pipeline:1.0.1 .
    ```

2. **Run the container**:
    ```bash
    docker run -p 8000:8000 agi-pipeline:1.0.1
    ```

## Governance & Compliance

This project enforces strict governance standards for AGI development.

- **Governance Artifacts**: Located in `gstack_artifacts/`.
- **Validation**: Run `make verify-governance` to ensure all artifacts meet compliance requirements.
- **Monitoring**: `omni_sentinel_24h_monitor.py` tracks G-SRI and attestation status.

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for our community standards.

## Citation

If you use this software in your research, please cite it as follows:

```bibtex
@software{Tun_AGI-Pipeline_2024,
author = {Tun, Kyaw T.},
doi = {10.5281/zenodo.14504697},
month = {12},
title = {{AGI-Pipeline}},
url = {https://github.com/OneFineStarstuff/AGI-Pipeline},
version = {1.0.0},
year = {2024}
}
```

Refer to [CITATION.cff](CITATION.cff) for more details.

## License

This project is licensed under the [MIT License](LICENSE).
