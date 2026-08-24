"""BugBounty MCP Server public package API."""

__version__ = "2.2.0"
__author__ = "Gokul AP"
__email__ = "apgokul008@gmail.com"

from .config import BugBountyConfig
from .server import BugBountyMCPServer

__all__ = ["BugBountyConfig", "BugBountyMCPServer", "__version__"]
