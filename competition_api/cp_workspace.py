import asyncio
import contextlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from aiofile import async_open
from git import Repo
from redis.asyncio import Redis
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import Auditor
from competition_api.audit.types import EventType, TimeoutContext
from competition_api.cp_registry import CPRegistry
from competition_api.flatfile import Flatfile, StorageType, archived_tarball
from competition_api.tasks.results import Archive, OutputMessage, OutputType

LOGGER = get_logger(__name__)


class BadReturnCode(Exception):
    pass


async def run(func, *args, stdin=None, timeout=3600, **kwargs):
    await LOGGER.adebug("%s %s %s", func, args, kwargs)
    proc = await asyncio.create_subprocess_exec(
        func,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        stdin=asyncio.subprocess.PIPE if stdin else None,
        **kwargs,
    )

    stdout, stderr = await asyncio.wait_for(
        proc.communicate(input=stdin.encode("utf8") if stdin else None),
        timeout=timeout,
    )

    return_code = proc.returncode

    # Program outputs may not be decodeable when POV blobs are passed to them
    await LOGGER.adebug("Process stdout: %s", stdout.decode("utf8", errors="ignore"))
    await LOGGER.adebug("Process stderr: %s", stderr.decode("utf8", errors="ignore"))

    return return_code, stdout, stderr


class CPWorkspace(contextlib.AbstractAsyncContextManager):
    def __init__(
        self,
        cp_name: str,
        auditor: Auditor,
        artifact_key: str,
        redis: Redis,
        azure_container: str,
        container_sas: str,
    ):
        cp = CPRegistry.instance().get(cp_name)
        if cp is None:
            raise ValueError(f"cp_name {cp_name} does not exist")
        self.azure_container = azure_container
        self.container_sas = container_sas
        self.redis = redis
        self.auditor = auditor
        self.artifact_key = artifact_key
        self.cp = cp
        self.cp_name = cp_name
        self.project_yaml: dict[str, Any]
        self.repo: Repo
        self.run_env: dict[str, str]
        self.src_repo: Repo | None
        self.workdir: Path

    async def __aenter__(self):
        # Make working copies
        self.workdir = self.cp.copy()
        self.project_yaml = self.cp.project_yaml

        self.repo = Repo(self.workdir)
        self.src_repo = None

        self.run_env = {
            "DOCKER_IMAGE_NAME": self.project_yaml["docker_image"],
            "DOCKER_HOST": os.environ.get("DOCKER_HOST", ""),
        }

        internal_dir = self.workdir / ".internal_only"
        if os.path.isdir(internal_dir):
            self.run_env["DOCKER_EXTRA_ARGS"] = f"-v {internal_dir}:/.internal_only"

        await LOGGER.adebug("Workspace: setup")
        return self

    async def __aexit__(self, _exc_type, _exc, _tb):
        shutil.rmtree(self.workdir, ignore_errors=True)

    @property
    def output_dir(self) -> Path:
        return self.workdir / "out" / "output"

    def command_output_dir(self, command) -> Path | None:
        try:
            dirname = [
                p
                for p in sorted(os.listdir(self.output_dir), reverse=True)
                if p.endswith(command)
            ][0]
            path = self.output_dir / dirname

            if not os.path.isdir(path):
                return None

            return path

        except (FileNotFoundError, IndexError):
            return None

    async def archive_output(
        self, auditor: Auditor, return_code: int | None, command: str
    ):
        path = self.command_output_dir(command)
        if path is None:
            await LOGGER.ainfo("No output produced for command %s", command)
            return
        with tempfile.TemporaryDirectory() as tempdir:
            filename: str | None = None
            async with archived_tarball(
                tempdir, prefix=f"output-{self.artifact_key}-{self.cp_name}-{command}-"
            ) as tarball:
                tarball.add(path, arcname=path.name)
                filename = str(tarball.name)

            async with async_open(filename, mode="rb") as file:
                flatfile = Flatfile(
                    self.azure_container,
                    contents=await file.read(),
                    container_sas=self.container_sas,
                )
                await flatfile.write(to=StorageType.AZUREBLOB)

                common_kwargs = {
                    "sha256": flatfile.sha256,
                    "filename": os.path.basename(filename),
                }
                await self.redis.publish(
                    v.get("redis.channels.results"),
                    OutputMessage(
                        message_type=OutputType.ARCHIVE,
                        content=Archive(
                            **common_kwargs, azure_container=self.azure_container
                        ),
                    ).model_dump_json(),
                )
                await auditor.emit(
                    EventType.CP_OUTPUT_ARCHIVED,
                    **common_kwargs,
                    cp_name=self.cp_name,
                    return_code=return_code,
                    command=command,
                )

    def set_src_repo(self, ref: str):
        source = self.cp.source_from_ref(ref)

        if source is None:
            self.src_repo = None
            return

        self.src_repo = Repo(self.workdir / "src" / source)

    def sanitizer(self, sanitizer_id: str) -> str | None:
        return self.project_yaml.get("sanitizers", {}).get(sanitizer_id)

    def harness(self, harness_id: str) -> str | None:
        return self.project_yaml.get("harnesses", {}).get(harness_id, {}).get("name")

    def current_commit(self) -> str | None:
        if self.src_repo is None:
            return None
        return self.src_repo.head.commit.hexsha

    def checkout(self, ref: str):
        LOGGER.debug("Workspace: checkout %s", ref)

        if self.src_repo is None:
            raise NotImplementedError

        self.src_repo.git.checkout(ref, force=True)

        LOGGER.debug("Checked out %s", self.current_commit())

    async def build(self, source: str, patch_sha256: str | None = None) -> bool:
        command = "build"
        await LOGGER.adebug(
            f"Workspace: {command}"
            + (f" with patch {patch_sha256}" if patch_sha256 else "")
        )

        try:
            if patch_sha256 is None:
                return_code, _, _ = await run(
                    "./run.sh",
                    "-x",
                    "-v",
                    command,
                    cwd=self.workdir,
                    env=self.run_env,
                    timeout=600,
                )

            else:
                patch = Flatfile(
                    self.azure_container,
                    contents_hash=patch_sha256,
                    container_sas=self.container_sas,
                )
                await patch.read(from_=StorageType.AZUREBLOB)
                await patch.write(to=StorageType.FILESYSTEM)
                return_code, _, _ = await run(
                    "./run.sh",
                    "-x",
                    "-v",
                    command,
                    patch.filename,
                    source,
                    cwd=self.workdir,
                    env=self.run_env,
                    timeout=600,
                )

            await self.archive_output(self.auditor, return_code, command)
            return return_code == 0
        except TimeoutError:
            await self.auditor.emit(EventType.TIMEOUT, context=TimeoutContext.BUILD)
            return False

    async def check_sanitizers(self, blob_sha256: str, harness: str) -> set[str]:
        blob = Flatfile(
            self.azure_container,
            contents_hash=blob_sha256,
            container_sas=self.container_sas,
        )
        await blob.read(from_=StorageType.AZUREBLOB)
        await blob.write(to=StorageType.FILESYSTEM)
        await LOGGER.adebug(
            "Workspace: check sanitizers on harness %s with blob (hash %s)",
            harness,
            blob.sha256,
        )

        command = "run_pov"
        try:
            return_code, _, _ = await run(
                "./run.sh",
                "-x",
                "-v",
                command,
                blob.filename,
                self.harness(harness),
                cwd=self.workdir,
                env=self.run_env,
                timeout=600,
            )
        except TimeoutError as exc:
            await self.auditor.emit(
                EventType.TIMEOUT, context=TimeoutContext.CHECK_SANITIZERS
            )
            raise BadReturnCode from exc

        if return_code != 0:
            raise BadReturnCode

        await self.archive_output(self.auditor, return_code, command)
        pov_output_path = self.command_output_dir(command)

        triggered: set[str] = set()
        if pov_output_path is not None:
            for file in [
                pov_output_path / "stderr.log",
                pov_output_path / "stdout.log",
            ]:
                try:
                    async with async_open(file, "r", encoding="utf8") as f:
                        async for line in f:
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
        try:
            command = "run_tests"
            return_code, _, _ = await run(
                "./run.sh",
                "-x",
                "-v",
                command,
                cwd=self.workdir,
                env=self.run_env,
                timeout=600,
            )
            await self.archive_output(self.auditor, return_code, command)
            return return_code == 0
        except TimeoutError:
            await self.auditor.emit(
                EventType.TIMEOUT, context=TimeoutContext.RUN_FUNCTIONAL_TESTS
            )
            return False
