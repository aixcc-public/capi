# pylint: disable=unused-argument
from uuid import uuid4

import redis.asyncio as redis

from competition_api.audit import Auditor
from competition_api.cp_workspace import CPWorkspace


class TestCPWorkspace:
    @staticmethod
    async def test_init(
        test_project_yaml,
        repo,
        container_name,
        container_sas,
    ):
        async with CPWorkspace(
            test_project_yaml["cp_name"],
            Auditor(),
            str(uuid4()),
            redis.Redis(),
            container_name,
            container_sas,
        ) as workspace:
            assert workspace.workdir
            assert workspace.project_yaml == test_project_yaml
            assert workspace.repo
