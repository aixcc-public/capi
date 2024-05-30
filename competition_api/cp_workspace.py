import asyncio
import os
import pathlib
import shutil
import tempfile

from git import Repo
from ruamel.yaml import YAML as RuamelYaml
from structlog.stdlib import get_logger
from vyper import v

YAML = RuamelYaml(typ="safe")
LOGGER = get_logger(__name__)


async def run(func, *args, stdin=None, **kwargs):
    await LOGGER.adebug("%s %s %s", func, args, kwargs)
    proc = await asyncio.create_subprocess_exec(
        func,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin else None,
        **kwargs,
    )
    stdout, stderr = await proc.communicate(
        input=stdin.encode("utf8") if stdin else None
    )
    return_code = proc.returncode

    await LOGGER.adebug(stdout.decode("utf8"))
    await LOGGER.adebug(stderr.decode("utf8"))

    return return_code, stdout, stderr


class CPWorkspace:
    def __init__(self, git_repo_url):
        self.workdir = pathlib.Path(tempfile.mkdtemp(dir=v.get("tempdir")))
        self._repo_url = git_repo_url

        shutil.copytree(self._repo_url, self.workdir, dirs_exist_ok=True)

        self.repo = Repo(self.workdir)
        self.src_repo = Repo(self.workdir / "src" / "samples")

        self.project_yaml = YAML.load(self.workdir / "project.yaml")

        self.run_env = {
            "DOCKER_IMAGE_NAME": self.project_yaml["docker_image"],
            "DOCKER_HOST": os.environ.get("DOCKER_HOST", ""),
        }

    def __del__(self):
        shutil.rmtree(self.workdir)

    def sanitizer(self, sanitizer_id: str) -> str | None:
        return self.project_yaml.get("sanitizers", {}).get(sanitizer_id)

    def harness(self, harness_id: str) -> str | None:
        return self.project_yaml.get("harnesses", {}).get(harness_id, {}).get("name")

    def current_commit(self) -> str:
        if self.src_repo is None:
            raise NotImplementedError
        return self.src_repo.head.commit.hexsha

    async def setup(self):
        await LOGGER.adebug("Workspace: setup")
        await run(
            "docker",
            "login",
            "ghcr.io",
            "-u",
            os.environ.get("GITHUB_USER", ""),
            "--password-stdin",
            stdin=os.environ.get("GITHUB_TOKEN", ""),
        )
        await run("docker", "pull", self.project_yaml["docker_image"])

    def checkout(self, ref: str):
        LOGGER.debug("Workspace: checkout %s", ref)

        if self.src_repo is None:
            raise NotImplementedError

        self.src_repo.git.checkout(ref)

        LOGGER.debug("Checked out %s", self.current_commit())

    async def build(self, patch: bytes | None = None) -> bool:
        await LOGGER.adebug(
            "Workspace: build"
            + (f" with patch {patch.decode('utf8')}" if patch else "")
        )
        with open(self.workdir / ".env.project", "w+", encoding="utf8") as env:
            env.write(
                f'DOCKER_VOL_ARGS="-v {self.workdir}/work:/work '
                f"-v {self.workdir}/src:/src "
                f"-v {self.workdir}/out:/out "
                f'-v {self.workdir}/.internal_only:/.internal_only"\n'
            )

        if patch is None:
            return_code, stdout, stderr = await run(
                "./run.sh", "build", cwd=self.workdir, env=self.run_env
            )

        else:
            with tempfile.NamedTemporaryFile(
                delete_on_close=False, dir=v.get("tempdir")
            ) as patchfile:
                patchfile.write(patch)
                patchfile.close()

                await LOGGER.adebug("Created patch file at %s", patchfile.name)

                return_code, stdout, stderr = await run(
                    "./run.sh",
                    "build",
                    patchfile.name,
                    "samples",
                    cwd=self.workdir,
                    env=self.run_env,
                )

        return (
            return_code == 0
            and "Error" not in stdout.decode("utf8")
            and "Error" not in stderr.decode("utf8")
        )

    async def check_sanitizers(self, blob: bytes, harness: str) -> set[str]:
        await LOGGER.adebug(
            "Workspace: check sanitizers on harness %s with blob (size %s)",
            harness,
            len(blob),
        )
        with tempfile.NamedTemporaryFile(
            delete_on_close=False, dir=v.get("tempdir")
        ) as blobfile:
            blobfile.write(blob)
            blobfile.close()

            await run(
                "./run.sh",
                "run_pov",
                blobfile.name,
                self.harness(harness),
                cwd=self.workdir,
                env=self.run_env,
            )

            output_dir = self.workdir / "out" / "output"
            pov_output_path = [
                p
                for p in sorted(os.listdir(output_dir), reverse=True)
                if p.endswith("run_pov")
            ][0]

            triggered: set[str] = set()
            for file in [
                output_dir / pov_output_path / "stderr.log",
                output_dir / pov_output_path / "stdout.log",
            ]:
                try:
                    with open(file, "r", encoding="utf8") as f:
                        for line in f:
                            for key, sanitizer in self.project_yaml[
                                "sanitizers"
                            ].items():
                                if sanitizer in line:
                                    triggered.add(key)
                except FileNotFoundError:
                    await LOGGER.awarning("%s not found", file)

            return triggered

    async def run_functional_tests(self) -> bool:
        await LOGGER.adebug("Workspace: run tests")
        return_code, _, _ = await run(
            "./run.sh", "run_tests", cwd=self.workdir, env=self.run_env
        )
        return return_code == 0
