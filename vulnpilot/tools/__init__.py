"""Tool plugins. Importing this package registers every built-in tool."""

# Import side-effects populate the registry via @register.
from . import (
    http_probe,  # noqa: F401,E402
    nuclei,  # noqa: F401,E402
    subfinder,  # noqa: F401,E402
    tls_probe,  # noqa: F401,E402
)
from .base import Tool, register, registry  # noqa: F401

__all__ = ["Tool", "registry", "register"]
