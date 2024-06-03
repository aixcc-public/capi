import os
import pathlib
import shutil
import tempfile
from copy import deepcopy
from threading import RLock
from typing import Any

from ruamel.yaml import YAML as RuamelYaml
from structlog.stdlib import get_logger
from vyper import v

YAML = RuamelYaml(typ="safe")
LOGGER = get_logger(__name__)


class CP:
    def __init__(self, name, root_dir, project_yaml):
        self.name = name
        self.root_dir = root_dir
        self._project_yaml = project_yaml

    def copy(self) -> pathlib.Path:
        workdir = tempfile.mkdtemp(dir=v.get("tempdir"))
        shutil.copytree(self.root_dir, workdir, dirs_exist_ok=True)
        return pathlib.Path(workdir)

    @property
    def project_yaml(self) -> dict[str, Any]:
        return deepcopy(self._project_yaml)


class CPRegistry:
    _instance = None
    _lock = RLock()

    def __init__(self):
        self._registry = {}

        if self._registry:
            return

        self._load_from_disk()

    def _load_from_disk(self):
        with CPRegistry._lock:
            cp_root = v.get("cp_root")

            if not cp_root:
                LOGGER.warning(
                    "Bailing on initializing CPRegistry because cp_root was None"
                )
                return

            for item in os.listdir(cp_root):
                item = pathlib.Path(cp_root) / item
                if os.path.isdir(item) and os.path.isfile(item / "project.yaml"):
                    project_yaml = YAML.load(item / "project.yaml")
                    if not (name := project_yaml.get("cp_name")):
                        LOGGER.warning(
                            "project.yaml in %s missing cp_name key. Skipping it.", item
                        )
                        continue
                    self._registry[name] = CP(name, item, project_yaml)
                    LOGGER.info("Loaded cp %s", name)
                else:
                    LOGGER.info(
                        "Item %s in %s does not look like a challenge problem",
                        item,
                        v.get("cp_root"),
                    )

    def get(self, cp_name) -> CP | None:
        return self._registry.get(cp_name)

    def has(self, cp_name) -> bool:
        return cp_name in self._registry

    @classmethod
    def instance(cls):
        if not cls._instance:
            with cls._lock:
                cls._instance = CPRegistry()
        return cls._instance
