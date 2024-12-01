import json
import logging
import logging.config
import os
import re


class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, dict):
            record.msg = json.dumps(record.msg)
        elif not isinstance(record.msg, str):
            record.msg = str(record.msg)

        sensitive_keys = ["password", "passwd", "pwd"]
        for key in sensitive_keys:
            # Redact sensitive data in double-quoted JSON-like format
            record.msg = re.sub(
                rf'("{key}":\s*")([^"]+)(")',  # noqa: E231
                r"\1****\3",
                record.msg,
                flags=re.IGNORECASE,
            )
            # Redact sensitive data in single-quoted JSON-like format
            record.msg = re.sub(
                rf"(\'{key}\':\s*\')([^\']+)(\')",  # noqa: E231
                r"\1****\3",
                record.msg,
                flags=re.IGNORECASE,
            )
            # Redact sensitive data in plain-text log messages
            record.msg = re.sub(
                r"(Password: )([^,]+)(,?)",
                r"\1****\3",
                record.msg,
            )

        if record.args:
            record.args = tuple(
                re.sub(
                    r"(Password: )([^,]+)(,?)",
                    r"\1****\3",
                    str(arg),
                )
                if isinstance(arg, str)
                else arg
                for arg in record.args
            )
        return True


def setup_logging():
    valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    if log_level not in valid_log_levels:
        log_level = "INFO"

    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s - %(levelname)s - [%(name)s] %(message)s",  # noqa: E501
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "filters": ["sensitive_data_filter"],
            },
            "file": {
                "class": "logging.FileHandler",
                "filename": ("app.log"),
                "formatter": "default",
                "filters": ["sensitive_data_filter"],
            },
        },
        "filters": {
            "sensitive_data_filter": {
                "()": SensitiveDataFilter,
            },
        },
        "root": {
            "level": log_level,
            "handlers": ["console", "file"],
        },
        "loggers": {
            "uvicorn": {
                "level": log_level,
                "handlers": ["console"],
                "propagate": False,
            },
        },
    }

    logging.config.dictConfig(logging_config)
    logging.debug("Logging setup complete.")
