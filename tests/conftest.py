# fixtures use dependency injection, so argument names must match fixture name
# and they're sometimes used just for their side effects
# pylint: disable=redefined-outer-name,unused-argument

import base64
import os
import pathlib
import tempfile
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from unittest import mock
from uuid import uuid4

import pytest
from azure.storage.blob import BlobServiceClient, generate_container_sas
from azure.storage.blob._blob_service_client import parse_connection_str
from fastapi.testclient import TestClient
from git import Repo
from pytest_docker_tools import container
from ruamel.yaml import YAML as RuamelYaml
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from vyper import v

from competition_api import cp_registry
from competition_api.config import init_vyper
from competition_api.db import GeneratedPatch, Token, VulnerabilityDiscovery
from competition_api.db.common import Base
from competition_api.db.session import db_session
from competition_api.flatfile import Flatfile, StorageType
from competition_api.main import app
from competition_api.models.types import FeedbackStatus
from tests.lib.auditor import RecordingAuditor
from tests.lib.patch import build_patch

ENV = {"POSTGRES_PASSWORD": "secret", "POSTGRES_USER": "capi", "POSTGRES_DB": "capi"}

YAML = RuamelYaml(typ="safe")

FAKE_CP_NAME = "fakecp"


@pytest.fixture(autouse=True)
def mock_conn_holder(db_config):
    # Pytest does not play well with shared async connection pools
    with mock.patch(
        "competition_api.db.session.CONNECTION_HOLDER.get_session_class",
        side_effect=lambda: async_sessionmaker(
            create_async_engine(url=v.get("database.url")),
            expire_on_commit=False,
            class_=AsyncSession,
        ),
    ):
        yield


@pytest.fixture
def test_project_yaml():
    return {
        "cp_name": FAKE_CP_NAME,
        "docker_image": FAKE_CP_NAME,
        "sanitizers": {
            "id_1": "BCSAN: you wrote bad code",
            "id_2": "LAMESAN: your code is lame",
            "id_3": "uggo: bad uggo code here",
        },
        "harnesses": {"id_1": {"name": "test_harness"}},
        "cp_sources": {
            "primary": {"ref": "v1.1.0"},
            "secondary/nested-folder": {"ref": "v3.0.0"},
            "tertiary": {},
        },
    }


@pytest.fixture
def cp_root(tmpdir):
    cp_root_dir = pathlib.Path(tmpdir) / "cp_root"
    v.set("cp_root", cp_root_dir)
    return cp_root_dir


@pytest.fixture
def repo(cp_root, test_project_yaml):
    repo_dir = cp_root / FAKE_CP_NAME

    project = "project.yaml"
    repo = Repo.init(repo_dir)

    YAML.dump(test_project_yaml, repo_dir / project)
    repo.index.add([project])
    repo.index.commit("initial")

    for source, source_info in test_project_yaml.get("cp_sources", {}).items():
        cp_src_path = repo_dir / "src" / source
        os.makedirs(cp_src_path, exist_ok=True)
        src_repo = Repo.init(cp_src_path)
        dummy_file = os.path.join(src_repo.working_dir, "file")

        latest = src_repo.git.head
        for content in ["content", "more content"]:
            with open(dummy_file, "a", encoding="utf8") as f:
                f.write(f"{content} {source}")

            src_repo.index.add([dummy_file])
            latest = src_repo.index.commit("initial")

        src_repo.create_head(source_info.get("ref", "main"), latest)

    return repo


@pytest.fixture(autouse=True)
def rebuild_cp_registry(repo):
    cp_registry.CPRegistry.instance()._load_from_disk()  # pylint: disable=protected-access


@pytest.fixture
def fake_cp():
    name = FAKE_CP_NAME
    return name


@pytest.fixture
def client():
    return TestClient(app)


azurite_container = container(  # pylint: disable=no-value-for-parameter
    image="mcr.microsoft.com/azure-storage/azurite",
    scope="session",
    ports={"10000/tcp": None},
    command=["azurite", "--blobHost", "0.0.0.0"],
)

redis_container = container(  # pylint: disable=no-value-for-parameter
    image="redis:6-alpine", scope="session", ports={"6379/tcp": None}
)

db_container = container(  # pylint: disable=no-value-for-parameter
    image="postgres:16",
    scope="session",
    environment=ENV,
    ports={"5432/tcp": None},
    # this makes postgres log queries
    # command=["postgres", "-c", "log_statement=all"],
)


@pytest.fixture
def container_name():
    return "worker-00000000-0000-0000-0000-000000000000"


@pytest.fixture(autouse=True)
def azureblob(azurite_container, container_name):
    host, port = azurite_container.get_addr("10000/tcp")
    v.set(
        "azure.storage_connection_string",
        (
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
            "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/"
            f"KBHBeksoGMGw==;BlobEndpoint=http://{host}:{port}/devstoreaccount1;"
        ),
    )

    blobsvc = BlobServiceClient.from_connection_string(
        v.get("azure.storage_connection_string")
    )

    blobsvc.create_container(container_name)
    init_vyper()
    yield blobsvc
    blobsvc.delete_container(container_name)
    for blobctr in blobsvc.list_containers():
        blobsvc.delete_container(blobctr)


@pytest.fixture
def container_sas(container_name, azureblob):
    _, _, components = parse_connection_str(
        v.get("azure.storage_connection_string"), None, "blob"
    )
    if not isinstance(components, dict):
        raise RuntimeError("Storage connection string was not a dict")

    yield generate_container_sas(
        account_name=azureblob.account_name,
        container_name=container_name,
        account_key=components["account_key"],
        permission="rw",
        expiry=datetime.now(timezone.utc) + timedelta(days=1),
    )


@pytest.fixture(autouse=True)
def redis_config(redis_container):
    host, port = redis_container.get_addr("6379/tcp")
    v.set("redis.host", host)
    v.set("redis.port", port)

    init_vyper()


@pytest.fixture(autouse=True)
async def db_config(db_container):
    v.set("database.password", ENV["POSTGRES_PASSWORD"])
    v.set("database.username", ENV["POSTGRES_USER"])
    v.set("database.name", ENV["POSTGRES_DB"])

    host, port = db_container.get_addr("5432/tcp")
    v.set("database.host", host)
    v.set("database.port", port)

    init_vyper()

    engine = create_async_engine(url=v.get("database.url"))
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with create_async_engine(url=v.get("database.url")).begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture(autouse=True)
def tempdirs(tmpdir):
    v.set("tempdir", tmpdir)
    v.set("flatfile_dir", tmpdir)


@pytest.fixture(autouse=True)
def audit_sink():
    with tempfile.NamedTemporaryFile(delete_on_close=False) as auditfile:
        auditfile.close()

        v.set("audit.file", auditfile.name)

        yield


@pytest.fixture
async def admin_creds(db_config):
    async with db_session() as db:
        return await Token.upsert(db, admin=True)


@pytest.fixture
def admin_auth_header(admin_creds):
    creds = base64.b64encode(
        f"{admin_creds[0]}:{admin_creds[1]}".encode("utf8")
    ).decode("utf8")
    return {"Authorization": f"Basic {creds}"}


@pytest.fixture
async def creds(db_config):
    async with db_session() as db:
        return await Token.upsert(db)


@pytest.fixture
def auth_header(creds):
    creds = base64.b64encode(f"{creds[0]}:{creds[1]}".encode("utf8")).decode("utf8")
    return {"Authorization": f"Basic {creds}"}


async def _create_and_return(db, table, row):
    db_row = (await db.execute(table.insert_returning(**row))).fetchone()

    row["status"] = db_row.status.value
    row["id"] = str(db_row.id)

    return row


@pytest.fixture
async def fake_vds_dict(creds, fake_cp, container_name):
    blob = Flatfile(container_name, contents=b"fake\n")
    await blob.write(to=StorageType.AZUREBLOB)

    return MappingProxyType(
        {
            "team_id": creds[0],
            "cp_name": fake_cp,
            "pou_commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
            "pou_sanitizer": "id_1",
            "pov_harness": "id_1",
            "pov_data_sha256": blob.sha256,
        }
    )


@pytest.fixture
async def fake_vds(fake_vds_dict):
    fake_vds_dict = {**fake_vds_dict}
    async with db_session() as db:
        return await _create_and_return(db, VulnerabilityDiscovery, fake_vds_dict)


@pytest.fixture
async def fake_accepted_vds(fake_cp, creds, container_name):
    blob = Flatfile(container_name, contents=b"fake\n")
    await blob.write(to=StorageType.AZUREBLOB)

    row = {
        "team_id": creds[0],
        "cp_name": fake_cp,
        "pou_commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
        "pou_sanitizer": "id_1",
        "pov_harness": "id_1",
        "pov_data_sha256": blob.sha256,
        "status": FeedbackStatus.ACCEPTED,
        "cpv_uuid": uuid4(),
    }
    async with db_session() as db:
        return await _create_and_return(db, VulnerabilityDiscovery, row)


@pytest.fixture
async def fake_gp_dict(fake_accepted_vds, container_name):
    patch = Flatfile(container_name, contents=build_patch().encode("utf8"))
    await patch.write(to=StorageType.AZUREBLOB)
    return MappingProxyType(
        {"data_sha256": patch.sha256, "cpv_uuid": fake_accepted_vds["cpv_uuid"]}
    )


@pytest.fixture
async def fake_gp(fake_gp_dict):
    fake_gp_dict = {**fake_gp_dict}
    async with db_session() as db:
        return await _create_and_return(db, GeneratedPatch, fake_gp_dict)


@pytest.fixture
def auditor(creds):
    aud = RecordingAuditor()
    aud.push_context(team_id=creds[0])
    return aud


@pytest.fixture
def mock_get_auditor(auditor):
    def func(*_args, **_kwargs):
        return auditor

    return func
