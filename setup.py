from setuptools import find_packages, setup

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
        "nest_asyncio",
    ],
    extras_require={"governance": ["jsonschema"]},
    entry_points={"console_scripts": ["validate-gsifi-governance-assets=scripts.validate_gsifi_governance_assets:main"]},
)
