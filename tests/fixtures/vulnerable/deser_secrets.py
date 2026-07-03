"""Vulnerable fixture: unsafe deserialization + plaintext/world-readable secret storage."""
import os
import pickle

import torch
import yaml


def load_model_bad(path):
    # R1: torch.load without weights_only=True
    return torch.load(path)


def load_pickle_bad(blob):
    # R1: pickle.loads on untrusted bytes
    return pickle.loads(blob)


def load_config_bad(text):
    # R1: yaml.load without a SafeLoader
    return yaml.load(text)


def save_token_bad(token):
    # R2: secret-shaped path opened for write
    with open("api_token.txt", "w") as f:
        f.write(token)


def save_creds_bad(secret_value):
    # R2: secret-named variable written to an opened file
    with open("out.dat", "w") as fh:
        fh.write(secret_value)


def loosen_bad():
    # R3: world-readable permissions on a secret-shaped path
    os.chmod("credentials.json", 0o644)
