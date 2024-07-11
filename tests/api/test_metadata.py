from uuid import uuid4

import pytest
from vyper import v


class TestMetadata:
    @staticmethod
    @pytest.mark.parametrize("run_id", [None, uuid4()])
    def test_get_health(client, run_id):
        if run_id:
            v.set("run_id", run_id)

        resp = client.get("/metadata/")

        assert resp.status_code == 200
        assert resp.json() == {"run_id": str(v.get("run_id"))}
