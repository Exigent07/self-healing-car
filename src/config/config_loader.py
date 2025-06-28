import os
import yaml

class Config:
    def __init__(self, config_path="src/config/config.yaml"):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Config file not found: {config_path}")
        with open(config_path, "r") as file:
            self.config = yaml.safe_load(file)

    def get(self, *keys, default=None):
        val = self.config
        try:
            for key in keys:
                val = val[key]
            return val
        except (KeyError, TypeError):
            return default

    def __getitem__(self, key):
        return self.config.get(key)

    def __repr__(self):
        return repr(self.config)

CONFIG = Config()
