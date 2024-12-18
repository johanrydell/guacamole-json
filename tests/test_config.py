import os
import sys
import unittest
from unittest.mock import patch

from app.config import (
    ENV_DEFAULTS,
    PROJECT_DEFAULTS,
    ConfigError,
    load_config,
    validate_int,
)

# Add the root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConfigModule(unittest.TestCase):
    def setUp(self):
        # Clear environment variables for a clean slate
        self.clear_env_variables()

    def tearDown(self):
        # Ensure environment variables are clean after tests
        self.clear_env_variables()

    def clear_env_variables(self):
        for var in ENV_DEFAULTS.keys():
            os.environ.pop(var, None)
        for var in PROJECT_DEFAULTS.keys():
            os.environ.pop(var, None)

    def test_default_config(self):
        config = load_config()
        # Check that all defaults are loaded correctly
        for key, default in {**ENV_DEFAULTS, **PROJECT_DEFAULTS}.items():
            self.assertEqual(config[key], default)

    def test_env_variable_override(self):
        os.environ["TLS_PORT"] = "8443"
        os.environ["TLS_LOG_LEVEL"] = "debug"
        config = load_config(force_reload=True)

        # Verify overridden values
        self.assertEqual(config["TLS_PORT"], 8443)  # Validated as an integer
        self.assertEqual(config["TLS_LOG_LEVEL"], "debug")

        # Verify other defaults remain unchanged
        self.assertEqual(config["TLS_CERT"], ENV_DEFAULTS["TLS_CERT"])

    def test_validate_int_valid_values(self):
        self.assertEqual(validate_int("123", 1, 1000, "Test Int"), 123)
        self.assertEqual(validate_int(456, 1, 1000, "Test Int"), 456)

    def test_validate_int_invalid_values(self):
        with self.assertRaises(ConfigError):
            validate_int("abc", 1, 1000, "Test Int")
        with self.assertRaises(ConfigError):
            validate_int("-1", 1, 1000, "Test Int")
        with self.assertRaises(ConfigError):
            validate_int("1001", 1, 1000, "Test Int")

    @patch.dict(os.environ, {"CERT_VALIDITY_DAYS": "700"})
    def test_valid_cert_validity_days(self):
        config = load_config(force_reload=True)
        self.assertEqual(config["CERT_VALIDITY_DAYS"], 700)

    @patch.dict(os.environ, {"CERT_VALIDITY_DAYS": "4000"})
    def test_invalid_cert_validity_days(self):
        with self.assertRaises(ConfigError):
            load_config(force_reload=True)

    def test_cached_config(self):
        # Load config once
        config1 = load_config()
        # Set environment variables after the first load
        os.environ["TLS_PORT"] = "1234"
        # Load config again
        config2 = load_config()
        # Ensure cached config is returned
        self.assertEqual(config1, config2)
        self.assertNotEqual(config2["TLS_PORT"], 1234)  # Cached, not updated


if __name__ == "__main__":
    unittest.main()
