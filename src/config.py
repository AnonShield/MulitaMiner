"""
Configuration management module for PDF Vulnerability Extractor.

This module handles configuration loading, validation, and environment setup.
"""

import os
import json
import logging
from typing import Dict, Any


class ConfigManager:
    """Manages application configuration and environment variables."""
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize configuration manager.
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self._validate_config()
        self._setup_environment()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file.
        
        Returns:
            Configuration dictionary
        """
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logging.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file '{self.config_path}' not found")
            logging.error("Please create a config.json file with OPENAI_API_KEY and MODEL_NAME")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in configuration file: {e}")
            raise
        except Exception as e:
            logging.error(f"Error loading configuration: {e}")
            raise
    
    def _validate_config(self) -> None:
        """Validate required configuration keys."""
        required_keys = ["OPENAI_API_KEY", "MODEL_NAME"]
        
        for key in required_keys:
            if key not in self.config:
                logging.error(f"Required configuration key '{key}' not found")
                raise ValueError(f"Missing required configuration: {key}")
        
        logging.info("Configuration validation passed")
    
    def _setup_environment(self) -> None:
        """Setup environment variables from configuration."""
        os.environ["OPENAI_API_KEY"] = self.config["OPENAI_API_KEY"]
        logging.info("Environment variables configured")
    
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get configuration setting.
        
        Args:
            key: Configuration key
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)
    
    def get_model_name(self) -> str:
        """Get configured model name.
        
        Returns:
            Model name string
        """
        return self.config["MODEL_NAME"]
    
    def get_openai_api_key(self) -> str:
        """Get OpenAI API key.
        
        Returns:
            API key string
        """
        return self.config["OPENAI_API_KEY"]


def setup_logging() -> None:
    """Setup logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Suppress HTTP request logs from LangChain and OpenAI
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)
    logging.getLogger("langchain").setLevel(logging.WARNING)
    logging.getLogger("langchain_openai").setLevel(logging.WARNING)
    logging.getLogger("langchain_community").setLevel(logging.WARNING)
    logging.getLogger("langchain_core").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    # logging.getLogger("httpcore").setLevel(logging.WARNING)  # Uncomment if needed