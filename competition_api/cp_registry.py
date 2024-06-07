import os
import pathlib
import shutil
import tempfile
from copy import deepcopy
from threading import RLock
from typing import Any

import git
from ruamel.yaml import YAML as RuamelYaml
from structlog.stdlib import get_logger
from vyper import v

YAML = RuamelYaml(typ="safe")
LOGGER = get_logger(__name__)


class CP:
    def __init__(self, name: str, root_dir: pathlib.Path, project_yaml: dict[str, Any]):
        self.name = name
        self.root_dir = root_dir
        self._project_yaml = project_yaml

        self.sources = self._project_yaml.get("cp_sources", {})

    def copy(self) -> pathlib.Path:
        workdir = tempfile.mkdtemp(dir=v.get("tempdir"))
        shutil.copytree(self.root_dir, workdir, dirs_exist_ok=True)
        return pathlib.Path(workdir)

    def head_ref_from_ref(self, ref: str) -> str | None:
        source = self.source_from_ref(ref)
        if source is None:
            return None
        return self.sources[source].get("ref", "main")

    def source_from_ref(self, ref: str) -> str | None:
        if len(self.sources) == 1:
            return list(self.sources.keys())[0]

        for source in self.sources.keys():
            repo = git.Repo(self.root_dir / "src" / source)
            current = repo.head.commit.hexsha
            try:
                repo.git.checkout(ref)
            except git.exc.GitCommandError as exc:
                # Did we get this exception because the commit is not in this tree?
                if "fatal: unable to read tree" in exc.stderr:
                    # if so, that's expected, this is just not the source repo we want
                    continue
                # If not, blow up
                raise

            repo.git.checkout(current)
            return source

        # Ref not found in any of the sources
        return None

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
                    cp = CP(name, item, project_yaml)
                    if not cp.sources:
                        LOGGER.warning(
                            "project.yaml in %s has no sources.  Skipping it.", item
                        )
                        continue
                    self._registry[name] = cp
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
