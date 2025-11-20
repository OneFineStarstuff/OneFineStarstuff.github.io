import logging

def setup_logging(log_file='dashboard.log'):
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

    logger = logging.getLogger(__name__)
    logger.info('Logging setup complete')

# Example usage
# setup_logging()
# logger = logging.getLogger(__name__)
# logger.info('This is an info message')
# logger.error('This is an error message')
