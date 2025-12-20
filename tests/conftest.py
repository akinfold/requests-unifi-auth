import sys
import os

# ensure `src` is on sys.path so imports like `from requests_unifi_auth.auth import UnifiControllerAuth` work
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

