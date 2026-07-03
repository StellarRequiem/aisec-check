"""Safe fixture: safe deserialization + guarded secret handling. Should produce zero findings."""
import pickle  # noqa: F401  (imported but the safe path below never calls the unsafe loader)

import torch
import yaml


def load_model_safe(path):
    # safe: weights_only=True
    return torch.load(path, weights_only=True)


def load_config_safe(text):
    # safe: SafeLoader
    return yaml.load(text, Loader=yaml.SafeLoader)


def load_config_safe2(text):
    # safe: yaml.safe_load is a different call the unsafe rule does not flag
    return yaml.safe_load(text)


def read_only(path):
    # safe: read mode, and not a secret-shaped path
    with open(path, "r") as f:
        return f.read()
