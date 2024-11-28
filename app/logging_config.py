import json
import logging
import os
import pwd
import re


#
# We have to remove the password from any logs
# The best way is to do a filter for the log class
#
class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Ensure the message is a string before applying the regex
        if isinstance(record.msg, dict):
            record.msg = json.dumps(record.msg)  # Convert dict to string for filtering
        elif not isinstance(record.msg, str):
            record.msg = str(record.msg)  # Convert other types to string

        # Regular expression to find and replace passwords in double-quoted
        # and single-quoted formats
        record.msg = re.sub(
            r'("password":\s*")([^"]+)(")', r"\1****\3", record.msg
        )  # Handles double quotes
        record.msg = re.sub(
            r"(\'password\':\s*\')([^\']+)(\')", r"\1****\3", record.msg
        )  # Handles single quotes
        return True


def setup_logging():
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    uid = os.geteuid()
    try:
        user_info = pwd.getpwuid(uid)
        username = user_info.pw_name
    except KeyError:
        username = "Unknown"
    logging.info(f"Running as user: {username} (UID: {uid})")

    # Apply the SensitiveDataFilter globally
    sensitive_filter = SensitiveDataFilter()

    # Add the filter to the root logger
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(sensitive_filter)
