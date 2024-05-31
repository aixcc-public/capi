import os
from hashlib import sha256
from pathlib import Path

from vyper import v

# Store alongside the audit log by default
v.set_default("flatfile_dir", "/var/log/capi")


class Flatfile:
    def __init__(
        self,
        contents: bytes | None = None,
        contents_hash: str | None = None,
    ):
        self.directory = Path(v.get("flatfile_dir"))

        if contents:
            self.sha256 = sha256(contents).hexdigest()
        elif contents_hash:
            self.sha256 = contents_hash
        else:
            raise ValueError("Flatfile needs either contents or a hash to look up")

        self.filename = self.directory / self.sha256

        if contents:
            with open(self.filename, "wb") as f:
                f.write(contents)
        elif contents_hash and not os.path.isfile(self.filename):
            raise ValueError("Supplied hash does not map to a real file on disk")
