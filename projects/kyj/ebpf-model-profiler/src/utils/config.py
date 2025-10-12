# src/utils/config.py - Configuration management
"""
Configuration management for the profiler.
Loads and validates configuration from YAML files.
"""

import yaml
from pathlib import Path
from typing import Dict, Any, Optional
import logging


class Config:
    """
    Configuration manager for the profiler.

    Loads configuration from YAML files and provides access to settings.
    """

    DEFAULT_CONFIG = {
        'profiler': {
            'sampling_rate': 1.0,
            'buffer_size': 256,
        },
        'syscalls': {
            'trace': ['openat', 'read', 'write', 'sendto', 'recvfrom', 'nanosleep'],
        },
        'filters': {
            'min_duration_us': 100,
        },
        'output': {
            'format': 'stdout',
            'prometheus_port': 9090,
        },
        'analysis': {
            'slow_threshold_us': 1000,
            'very_slow_threshold_us': 10000,
            'hotspot_time_threshold_percent': 10.0,
            'hotspot_count_threshold': 5,
        }
    }

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to YAML configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self.DEFAULT_CONFIG.copy()

        if config_file:
            self.load_from_file(config_file)

    def load_from_file(self, config_file: str):
        """
        Load configuration from YAML file.

        Args:
            config_file: Path to YAML file
        """
        config_path = Path(config_file)

        if not config_path.exists():
            self.logger.warning(f"Config file not found: {config_file}, using defaults")
            return

        try:
            with open(config_path, 'r') as f:
                loaded_config = yaml.safe_load(f)

            # Merge with defaults
            self._merge_config(self.config, loaded_config)
            self.logger.info(f"Loaded configuration from {config_file}")

        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            raise

    def _merge_config(self, base: Dict, override: Dict):
        """
        Recursively merge configuration dictionaries.

        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'profiler.buffer_size')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value by dot-notation key.

        Args:
            key: Configuration key (e.g., 'profiler.buffer_size')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def to_dict(self) -> Dict:
        """
        Get full configuration as dictionary.

        Returns:
            Configuration dictionary
        """
        return self.config.copy()

    def save_to_file(self, config_file: str):
        """
        Save current configuration to YAML file.

        Args:
            config_file: Path to output YAML file
        """
        config_path = Path(config_file)

        try:
            with open(config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)

            self.logger.info(f"Saved configuration to {config_file}")

        except Exception as e:
            self.logger.error(f"Failed to save config: {e}")
            raise
