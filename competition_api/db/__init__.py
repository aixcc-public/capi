# all models must be imported and added to __all__ for migration generation to work

from .auth import Token
from .gp import GeneratedPatch
from .session import db_session
from .vds import VulnerabilityDiscovery

__all__ = [
    "VulnerabilityDiscovery",
    "GeneratedPatch",
    "Token",
    "db_session",
]
