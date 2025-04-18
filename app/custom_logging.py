import logging
import os
import re

# Set the log level based on the environment variable
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()


class SensitiveDataFilter(logging.Filter):
    """
    A logging filter that redacts sensitive data (e.g., passwords, RSA keys)
    from log messages and arguments.
    """

    def __init__(self):
        super().__init__()
        self.sensitive_pattern = re.compile(
            r'(?i)(["\']?password["\']?\s*[:=]\s*[\'"]?)([^\'",\s]+)'
        )

        # Pattern to match an RSA key block
        self.rsa_key_pattern = re.compile(
            r"(-----BEGIN RSA PRIVATE KEY-----)(.*?)(-----END RSA PRIVATE KEY-----)",
            re.DOTALL,
        )

    def redact(self, message):
        """
        Redacts sensitive data from strings, dictionaries, or lists.
        """
        if isinstance(message, str):
            message = self.sensitive_pattern.sub(r"\1****", message)
            message = self.rsa_key_pattern.sub(r"\1\n****\n\3", message)
            return message
        elif isinstance(message, dict):
            return {k: self.redact(v) for k, v in message.items()}
        elif isinstance(message, list):
            return [self.redact(item) for item in message]
        return message

    def flatten_message(self, record):
        """
        Combines `record.msg` and `record.args` into a single, preformatted string.
        """
        if record.args:
            try:
                redacted_args = tuple(self.redact(arg) for arg in record.args)
                record.msg = record.msg % redacted_args
                record.args = None
            except Exception as e:
                logging.getLogger(__name__).error(
                    f"Error formatting log message: {e}", exc_info=True
                )
        else:
            record.msg = self.redact(record.msg)

    def filter(self, record):
        """
        Redacts sensitive data from the log record.
        """
        self.flatten_message(record)
        return True


def setup_logging():
    """
    Configures logging with a sensitive data filter.
    """
    if logging.root.handlers:
        return  # Avoid multiple initializations

    try:
        numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)

        # Configure a handler
        handler = logging.StreamHandler()
        handler.setLevel(numeric_level)

        # Add a formatter
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        # Attach the sensitive data filter
        sensitive_filter = SensitiveDataFilter()
        handler.addFilter(sensitive_filter)

        # Add handler to root logger
        logging.root.addHandler(handler)
        logging.root.setLevel(numeric_level)

        logging.getLogger(__name__).info(
            f"Logging initialized with sensitive data filter: {LOG_LEVEL}"
        )

    except Exception as e:
        logging.basicConfig(level=logging.INFO)
        logging.getLogger(__name__).error(
            f"Failed to set log level: {LOG_LEVEL}. Defaulting to INFO. Error: {e}"
        )


# Automatically setup logging
setup_logging()
