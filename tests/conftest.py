# fixtures use dependency injection, so argument names must match fixture name
# and they're sometimes used just for their side effects
# pylint: disable=redefined-outer-name,unused-argument

import base64
import os
import pathlib
import tempfile
from types import MappingProxyType
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from git import Repo
from pytest_asyncio import is_async_test
from pytest_docker_tools import container
from ruamel.yaml import YAML as RuamelYaml
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from vyper import v

from competition_api import cp_registry
from competition_api.config import init_vyper
from competition_api.db import GeneratedPatch, Token, VulnerabilityDiscovery
from competition_api.db.common import Base
from competition_api.db.session import db_session
from competition_api.flatfile import Flatfile
from competition_api.main import app
from competition_api.models.types import FeedbackStatus
from tests.lib.auditor import RecordingAuditor
from tests.lib.patch import build_patch

ENV = {"POSTGRES_PASSWORD": "secret", "POSTGRES_USER": "capi", "POSTGRES_DB": "capi"}

YAML = RuamelYaml(typ="safe")

FAKE_CP_NAME = "fakecp"


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
            "samples": {"ref": "v1.1.0"},
            "secondary": {"ref": "v3.0.0"},
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
                f.write(content)

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


db_container = container(  # pylint: disable=no-value-for-parameter
    image="postgres:16",
    scope="session",
    environment=ENV,
    ports={"5432/tcp": None},
    # this makes postgres log queries
    # command=["postgres", "-c", "log_statement=all"],
)


@pytest.fixture(autouse=True)
def db_config(db_container):
    v.set("database.password", ENV["POSTGRES_PASSWORD"])
    v.set("database.username", ENV["POSTGRES_USER"])
    v.set("database.name", ENV["POSTGRES_DB"])

    host, port = db_container.get_addr("5432/tcp")
    v.set("database.host", host)
    v.set("database.port", port)

    init_vyper()

    engine = create_engine(v.get("database.url"))
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db(db_config):
    engine = create_engine(v.get("database.url"))
    with sessionmaker(engine)() as session:
        yield session


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
async def creds():
    async with db_session() as db:
        yield await Token.create(db)


@pytest.fixture
def auth_header(creds):
    creds = base64.b64encode(f"{creds[0]}:{creds[1]}".encode("utf8")).decode("utf8")
    return {"Authorization": f"Basic {creds}"}


def _create_and_return(db, table, row):
    db_row = db.execute(table.insert_returning(**row))
    db_row = db_row.all()[0]
    db.commit()

    row["status"] = db_row.status.value
    row["id"] = str(db_row.id)

    return row


@pytest.fixture
async def fake_vds_dict(creds, fake_cp):
    blob = Flatfile(contents=b"fake\n")
    await blob.write()

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
def fake_vds(fake_vds_dict, db):
    fake_vds_dict = {**fake_vds_dict}
    return _create_and_return(db, VulnerabilityDiscovery, fake_vds_dict)


@pytest.fixture
async def fake_accepted_vds(db, fake_cp, creds):
    blob = Flatfile(contents=b"fake\n")
    await blob.write()

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
    return _create_and_return(db, VulnerabilityDiscovery, row)


@pytest.fixture
async def fake_gp_dict(fake_accepted_vds):
    patch = Flatfile(contents=build_patch().encode("utf8"))
    await patch.write()
    return MappingProxyType(
        {"data_sha256": patch.sha256, "cpv_uuid": fake_accepted_vds["cpv_uuid"]}
    )


@pytest.fixture
def fake_gp(fake_gp_dict, db):
    fake_gp_dict = {**fake_gp_dict}
    return _create_and_return(db, GeneratedPatch, fake_gp_dict)


def pytest_collection_modifyitems(items):
    pytest_asyncio_tests = (item for item in items if is_async_test(item))
    session_scope_marker = pytest.mark.asyncio(scope="session")
    for async_test in pytest_asyncio_tests:
        async_test.add_marker(session_scope_marker, append=False)


@pytest.fixture
def auditor(creds):
    return RecordingAuditor(creds[0])


@pytest.fixture
def mock_get_auditor(auditor):
    def func(*_args, **_kwargs):
        return auditor

    return func
