import logging
import os

# Set the log level based on the environment variable
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


def setup_logging():
    """
    Sets up basic logging configuration for the application.
    Logs to stdout with timestamps and a configurable log level.
    This function is idempotent, meaning it can be called multiple times safely.
    """
    try:
        # Clear existing handlers to avoid duplicate logs
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)

        # Validate the log level
        numeric_level = getattr(logging, LOG_LEVEL, None)
        if not isinstance(numeric_level, int):
            raise ValueError(f"Invalid log level: {LOG_LEVEL}")

        # Configure the root logger
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[logging.StreamHandler()],
        )

        logging.getLogger().info(f"Logging initialized with level: {LOG_LEVEL}")

    except Exception as e:
        # Fallback to default logging on error
        logging.basicConfig(level=logging.INFO)
        logging.getLogger().error(
            f"Failed to set log level: {LOG_LEVEL}. Defaulting to INFO. Error: {e}"
        )


# Call setup_logging to initialize logging immediately
setup_logging()
