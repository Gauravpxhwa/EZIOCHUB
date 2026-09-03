"""Makes `import shared.*` work from the tests directory.

The Function App runs with api/ as its working directory, so modules are
imported as `shared.config`, not `api.shared.config`. This mirrors that.
"""
import pathlib
import sys

API_ROOT = pathlib.Path(__file__).resolve().parent.parent / "api"
VENDORED = API_ROOT / ".python_packages" / "lib" / "site-packages"

for path in (API_ROOT, VENDORED):
    if path.exists() and str(path) not in sys.path:
        sys.path.insert(0, str(path))
