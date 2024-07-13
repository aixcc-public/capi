import contextlib
import tarfile
from enum import Enum
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import azure
from aiofile import async_open
from azure.storage.blob import BlobServiceClient
from structlog.stdlib import get_logger
from vyper import v

# Store alongside the audit log by default
v.set_default("flatfile_dir", "/var/log/capi")
LOGGER = get_logger(__name__)


class StorageType(Enum):
    FILESYSTEM = "filesystem"
    AZUREBLOB = "azureblob"


class Flatfile:
    def __init__(
        self,
        contents: bytes | None = None,
        contents_hash: str | None = None,
    ):
        self.directory = Path(v.get("flatfile_dir"))
        self._contents = contents
        self._blobsvc = BlobServiceClient.from_connection_string(
            v.get("azure.storage_connection_string")
        )

        if self._contents:
            self.sha256 = sha256(self._contents).hexdigest()
        elif contents_hash:
            self.sha256 = contents_hash
        else:
            raise ValueError("Flatfile needs either contents or a hash to look up")

        self._blob = self._blobsvc.get_blob_client(
            container=v.get("azure.blob_container_name"), blob=self.sha256
        )
        self.filename = self.directory / self.sha256

    async def write(self, to: StorageType = StorageType.FILESYSTEM):
        if self._contents is None:
            raise RuntimeError("Can't write None to storage")

        if to == StorageType.FILESYSTEM:
            await LOGGER.adebug(
                "Writing %s bytes to %s", len(self._contents or ""), self.filename
            )
            async with async_open(self.filename, "wb") as f:
                await f.write(self._contents)
        elif to == StorageType.AZUREBLOB:
            await LOGGER.adebug(
                "Writing %s bytes to blob %s:%s",
                len(self._contents or ""),
                v.get("azure.blob_container_name"),
                self.sha256,
            )
            try:
                self._blob.upload_blob(self._contents)
            except azure.core.exceptions.ResourceExistsError:
                await LOGGER.awarning("Blob with hash %s already exists", self.sha256)

    async def read(self, from_: StorageType = StorageType.FILESYSTEM) -> bytes:
        if from_ == StorageType.FILESYSTEM:
            await LOGGER.adebug("Reading content of %s", self.filename)
            async with async_open(self.filename, "rb") as f:
                self._contents = await f.read()
        elif from_ == StorageType.AZUREBLOB:
            await LOGGER.adebug(
                "Reading content of blob %s:%s",
                v.get("azure.blob_container_name"),
                self.sha256,
            )
            self._contents = self._blob.download_blob().readall()
        if self._contents is None:
            raise RuntimeError("No content found for file")
        return self._contents


@contextlib.asynccontextmanager
async def archived_tarball(tempdir, prefix="output-"):
    filename = f"{prefix}{uuid4()}.tar.xz"

    await LOGGER.ainfo("Creating new tarball at %s", filename)
    with tarfile.open(Path(tempdir) / filename, "w:xz") as tar:
        yield tar
