import contextlib
import tarfile
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import azure
from aiofile import async_open
from azure.storage.blob import (
    BlobClient,
    BlobServiceClient,
    ContainerClient,
    ContainerSasPermissions,
    generate_container_sas,
)
from azure.storage.blob._blob_service_client import parse_connection_str
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
        azure_container: str,
        contents: bytes | None = None,
        contents_hash: str | None = None,
        container_sas: str | None = None,
    ):
        self.directory = Path(v.get("flatfile_dir"))
        self._contents = contents
        self._blobsvc: BlobServiceClient | None = None
        self._azure_container = azure_container
        self._container_sas = container_sas
        self._account_key: str | None = None

        if v.get("azure.storage_connection_string"):
            blobsvc = BlobServiceClient.from_connection_string(
                v.get("azure.storage_connection_string")
            )
            _, _, _components = parse_connection_str(
                v.get("azure.storage_connection_string"), None, "blob"
            )
            if not isinstance(_components, dict):
                raise RuntimeError("Storage connection string was not a dict")
            self._account_key = _components["account_key"]

            try:
                blobsvc.create_container(azure_container)
                LOGGER.info("Created azure blob container %s", azure_container)
            except azure.core.exceptions.ResourceExistsError:
                LOGGER.info("Azure blob container %s already existed", azure_container)

            self._blobsvc = blobsvc

        if self._contents:
            self.sha256 = sha256(self._contents).hexdigest()
        elif contents_hash:
            self.sha256 = contents_hash
        else:
            raise ValueError("Flatfile needs either contents or a hash to look up")

        self.filename = self.directory / self.sha256

    def container_sas(self) -> str:
        if self._blobsvc is None or self._account_key is None:
            raise RuntimeError(
                "Tried to create a container SAS without elevated permissions"
            )

        container_client = self._blobsvc.get_container_client(
            container=self._azure_container
        )
        sas_token = generate_container_sas(
            account_name=self._blobsvc.account_name,
            container_name=self._azure_container,
            account_key=self._account_key,
            permission=ContainerSasPermissions(read=True, write=True, create=True),
            expiry=datetime.now(timezone.utc) + timedelta(hours=2),
        )

        return f"{container_client.url}?{sas_token}"

    def _blob_client(self) -> BlobClient:
        if self._blobsvc is not None:
            return self._blobsvc.get_blob_client(
                container=self._azure_container, blob=self.sha256
            )
        if self._container_sas is not None:
            return ContainerClient.from_container_url(
                self._container_sas
            ).get_blob_client(self.sha256)
        raise RuntimeError("Tried to create a Flatfile without Azure Blob access")

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
                self._azure_container,
                self.sha256,
            )
            try:
                self._blob_client().upload_blob(self._contents)
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
                self._azure_container,
                self.sha256,
            )
            self._contents = self._blob_client().download_blob().readall()
        if self._contents is None:
            raise RuntimeError("No content found for file")
        return self._contents


@contextlib.asynccontextmanager
async def archived_tarball(tempdir, prefix="output-"):
    filename = f"{prefix}{uuid4()}.tar.xz"

    await LOGGER.ainfo("Creating new tarball at %s", filename)
    with tarfile.open(Path(tempdir) / filename, "w:xz") as tar:
        yield tar
