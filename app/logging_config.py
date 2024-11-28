import json
import logging
import logging.config
import re


#
# We have to remove the password from any logs
# The best way is to do a filter for the log class
#
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Convert message to string if necessary
        if isinstance(record.msg, dict):
            record.msg = json.dumps(record.msg)
        elif not isinstance(record.msg, str):
            record.msg = str(record.msg)

        # Redact sensitive data in the main message
        record.msg = re.sub(r'("password":\s*")([^"]+)(")', r"\1****\3", record.msg)
        record.msg = re.sub(
            r"(\'password\':\s*\')([^\']+)(\')", r"\1****\3", record.msg
        )
        record.msg = re.sub(r"(Password: )([^,]+)(,?)", r"\1****\3", record.msg)

        # Redact sensitive data in arguments
        if record.args:
            record.args = tuple(
                re.sub(r"(Password: )([^,]+)(,?)", r"\1****\3", str(arg))
                if isinstance(arg, str)
                else arg
                for arg in record.args
            )
        return True


def setup_logging():
    log_level = "INFO"

    # Programmatic logging configuration
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["sensitive_data_filter"],
            },
        },
        "filters": {
            "sensitive_data_filter": {
                "()": SensitiveDataFilter,  # Reference your filter class here
            },
        },
        "root": {
            "level": log_level,
            "handlers": ["console"],
        },
        "loggers": {
            "uvicorn": {
                "level": log_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.access": {
                "level": log_level,
                "handlers": ["console"],
                "propagate": False,
            },
            "uvicorn.error": {
                "level": log_level,
                "handlers": ["console"],
                "propagate": False,
            },
        },
    }

    # Apply the logging configuration
    logging.config.dictConfig(logging_config)
    logging.debug("Programmatic logging configuration applied.")
