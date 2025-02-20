import configparser
import os
from pathlib import Path

class ConfigManager:
    """
    Handles reading and validating configuration from config.ini or environment variables.
    Environment variables override config.ini values where relevant.
    """

    def __init__(self, config_path='config.ini'):
        """
        Initialize the ConfigManager and load the config file.
        :param config_path: Path to the configuration file.
        """
        self.config_path = config_path
        self.config = configparser.ConfigParser()
        self._api_key = None
        self._api_url = None
        self._output_path = None
        self._subdomains_file = None

        self.load_config()

    def load_config(self):
        """
        Reads config file from disk and validates presence of critical fields.
        Environment variables override config file values.
        """
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        self.config.read(self.config_path)
        self.validate_config()

        # Prefer environment variables if available, else fallback to config.ini
        self._api_key = os.getenv('API_KEY', self.config['API']['key'])
        self._api_url = os.getenv('API_URL', self.config['API']['url'])

        # For output path and subdomains file, also check env vars
        self._output_path = os.getenv('OUTPUT_PATH', self.config['Settings']['output_path'])
        self._subdomains_file = os.getenv('SUBDOMAINS_FILE', self.config['Settings']['subdomains_file'])

    def validate_config(self):
        """
        Ensures required sections and keys exist in the config. 
        Raises ValueError if something is missing.
        """
        required_sections = ['API', 'Settings']
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required section in config: [{section}]")

        required_keys = {
            'API': ['key', 'url'],
            'Settings': ['output_path', 'subdomains_file']
        }

        for section, keys in required_keys.items():
            for key in keys:
                if key not in self.config[section]:
                    raise ValueError(f"Missing required key: {section}.{key}")

    def get_api_key(self) -> str:
        """Return the geolocation API key."""
        return self._api_key

    def get_api_url(self) -> str:
        """Return the geolocation API URL."""
        return self._api_url

    def get_output_path(self) -> Path:
        """Return the path for CSV output."""
        return Path(self._output_path)

    def get_subdomains_file(self) -> Path:
        """Return the subdomains file path."""
        return Path(self._subdomains_file)
