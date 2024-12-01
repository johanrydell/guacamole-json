import logging

from app.logging_config import setup_logging


def test_setup_logging_creates_root_logger():
    # Setup logging
    setup_logging()

    # Get the root logger
    root_logger = logging.getLogger()

    # Assert: Check if the root logger is configured correctly
    assert root_logger.level == logging.INFO
    assert len(root_logger.handlers) > 0

    # Assert: Console handler exists
    console_handler = any(
        isinstance(handler, logging.StreamHandler) for handler in root_logger.handlers
    )
    assert console_handler

    # Assert: File handler exists
    file_handler = any(
        isinstance(handler, logging.FileHandler) for handler in root_logger.handlers
    )
    assert file_handler
