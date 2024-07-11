from .gp import router as GPRouter
from .health import router as HealthRouter
from .metadata import router as MetadataRouter
from .vds import router as VDSRouter

__all__ = ["GPRouter", "HealthRouter", "VDSRouter", "MetadataRouter"]
