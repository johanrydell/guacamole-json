import logging
import os

logger = logging.getLogger(__name__)


def validate_file_path(file_path, file_type="file"):
    if not file_path or not os.path.exists(file_path):
        logger.error(f"Invalid {file_type}: {file_path}")
        return None
    return file_path
