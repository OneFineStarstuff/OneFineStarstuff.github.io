"""
NLP Module for the Enhanced AGI Pipeline.
"""

from loguru import logger
from transformers import T5ForConditionalGeneration, T5Tokenizer


class NLPModule:
    """
    A module for Natural Language Processing using the FLAN-T5 model.
    """

    def __init__(self):
        """
        Initializes the NLP model and tokenizer.
        """
        model_name = "google/flan-t5-small"
        # Pinning revision to a specific commit hash for security (Bandit B615)
        # Using a literal string in the call to satisfy Bandit.
        self.tokenizer = T5Tokenizer.from_pretrained(
            model_name, revision="0fc9ddf78a1e988dac52e2dac162b0ede4fd74ab"
        )
        self.model = T5ForConditionalGeneration.from_pretrained(
            model_name, revision="0fc9ddf78a1e988dac52e2dac162b0ede4fd74ab"
        )
        logger.info("NLP model loaded successfully.")

    def generate_text(self, prompt: str) -> str:
        """Generates text based on the provided prompt.

        Args:
            prompt (str): The input text to process.

        Raises:
            ValueError: If the prompt is empty.
        """
        if not prompt.strip():
            raise ValueError("Prompt cannot be empty.")
        logger.debug(f"Generating text for prompt: {prompt}")
        inputs = self.tokenizer(prompt, return_tensors="pt")
        outputs = self.model.generate(inputs["input_ids"], max_length=100)
        response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        logger.info(f"Generated response: {response}")
        return response
