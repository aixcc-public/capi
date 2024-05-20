import base64
from unittest import mock

import pytest
from sqlalchemy import select

from competition_api.db import GeneratedPatch
from competition_api.models.types import FeedbackStatus


class TestGP:
    @staticmethod
    @pytest.mark.parametrize(
        "body",
        [{"data": "ZmFrZQo="}],
    )
    def test_post(db, client, body, fake_accepted_vds, auth_header):
        body["cpv_uuid"] = str(fake_accepted_vds["cpv_uuid"])

        with mock.patch("competition_api.endpoints.gp.gp.TaskRunner", autospec=True):
            resp = client.post("/submission/gp/", json=body, headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        db_row = db.execute(select(GeneratedPatch)).fetchall()
        assert len(db_row) == 1
        db_row = db_row[0][0]

        data = base64.b64decode(body["data"])

        assert resp["gp_uuid"] == str(db_row.id)
        assert resp["status"] == FeedbackStatus.PENDING.value
        assert resp["patch_size"] == len(data)

        assert str(db_row.cpv_uuid) == body["cpv_uuid"]
        assert db_row.data == data
        assert db_row.status == FeedbackStatus.PENDING

    @staticmethod
    @pytest.mark.parametrize(
        "body",
        [{"data": "ZmFrZQo="}],
    )
    def test_post_bad(client, body, fake_vds, auth_header):
        body["cpv_uuid"] = fake_vds.get("cpv_uuid")
        resp = client.post("/submission/gp/", json=body, headers=auth_header)

        assert resp.status_code == 422

    @staticmethod
    def test_get(client, fake_gp, auth_header):
        resp = client.get(f"/submission/gp/{str(fake_gp['id'])}", headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        assert resp["status"] == fake_gp["status"]
        assert resp["gp_uuid"] == str(fake_gp["id"])
