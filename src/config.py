"""OwlGuard configuration."""
import os

# GitHub App
GITHUB_APP_ID = os.environ.get("OWLGUARD_APP_ID", "")
GITHUB_PRIVATE_KEY_PATH = os.environ.get("OWLGUARD_PRIVATE_KEY", "")
GITHUB_WEBHOOK_SECRET = os.environ.get("OWLGUARD_WEBHOOK_SECRET", "")

# Paths to OwlSec and OwlMind
CHARWIZ_SRC = os.environ.get("OWLGUARD_CHARWIZ_SRC", os.path.expanduser("~/charwiz/src"))

# Server
PORT = int(os.environ.get("OWLGUARD_PORT", "8800"))
HOST = os.environ.get("OWLGUARD_HOST", "0.0.0.0")

# Limits
MAX_FILES_PER_SCAN = 500
MAX_FIX_ATTEMPTS = 3
