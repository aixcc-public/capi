import contextlib
import os
import tarfile
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from aiofile import async_open
from structlog.stdlib import get_logger
from vyper import v

# Store alongside the audit log by default
v.set_default("flatfile_dir", "/var/log/capi")
LOGGER = get_logger(__name__)


class Flatfile:
    def __init__(
        self,
        contents: bytes | None = None,
        contents_hash: str | None = None,
    ):
        self.directory = Path(v.get("flatfile_dir"))
        self._contents = contents

        if self._contents:
            self.sha256 = sha256(self._contents).hexdigest()
        elif contents_hash:
            self.sha256 = contents_hash
        else:
            raise ValueError("Flatfile needs either contents or a hash to look up")

        self.filename = self.directory / self.sha256

        if contents_hash and not os.path.isfile(self.filename):
            raise ValueError("Supplied hash does not map to a real file on disk")

    async def write(self):
        await LOGGER.adebug(
            "Writing %s bytes to %s", len(self._contents or ""), self.filename
        )
        async with async_open(self.filename, "wb") as f:
            await f.write(self._contents)

    async def read(self) -> bytes | None:
        await LOGGER.adebug("Reading content of %s", self.filename)
        async with async_open(self.filename, "rb") as f:
            self._contents = await f.read()
            return self._contents


@contextlib.asynccontextmanager
async def archived_tarball(prefix="output-"):
    archive_dir = Path(v.get("flatfile_dir")) / "output"
    os.makedirs(archive_dir, exist_ok=True)
    filename: str | None = None

    while filename is None or os.path.exists(archive_dir / filename):
        filename = f"{prefix}{uuid4()}.tar.xz"

    await LOGGER.ainfo("Creating new tarball at %s", filename)
    with tarfile.open(archive_dir / filename, "w:xz") as tar:
        yield tar
