import base64
from unittest import mock

import pytest
from sqlalchemy import select

from competition_api.db import VulnerabilityDiscovery
from competition_api.models.types import FeedbackStatus


class TestVDS:
    @staticmethod
    @pytest.mark.parametrize(
        "body",
        [
            {
                "cp_name": "fakecp",
                "pou": {
                    "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                    "sanitizer": "id_1",
                },
                "pov": {"harness": "id_1", "data": "ZmFrZQo="},
            },
            {
                "cp_name": "fakecp",
                "pou": {
                    "commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                    "sanitizer": "id_1",
                },
                "pov": {
                    "harness": "id_1",
                    "data": "i4uLi4WLi4uLi4uLi4uLi4uLi4xQi4uLi4uLjIuLiw==",  # non-text patch
                },
            },
        ],
    )
    def test_post(db, client, body, auth_header):
        with mock.patch("competition_api.endpoints.vds.vds.TaskRunner", autospec=True):
            resp = client.post("/submission/vds/", json=body, headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        db_row = db.execute(select(VulnerabilityDiscovery)).fetchall()
        assert len(db_row) == 1
        db_row = db_row[0][0]

        assert resp["vd_uuid"] == str(db_row.id)
        assert resp["status"] == FeedbackStatus.PENDING.value
        assert resp["cp_name"] == body["cp_name"]

        assert db_row.pou_commit_sha1.lower() == body["pou"]["commit_sha1"].lower()
        assert db_row.pou_sanitizer == body["pou"]["sanitizer"]
        assert db_row.pov_harness == body["pov"]["harness"]
        assert db_row.pov_data == base64.b64decode(body["pov"]["data"])
        assert db_row.status == FeedbackStatus.PENDING

    @staticmethod
    @pytest.mark.parametrize(
        "row",
        [
            {
                "cp_name": "somecp",
                "pou_commit_sha1": "b124160e9fac8952706a6f0d5d6f71c85df9e77c",
                "pou_sanitizer": "id_1",
                "pov_harness": "id_1",
                "pov_data": b"fake\n",
            }
        ],
    )
    def test_get(db, client, row, creds, auth_header):
        row["team_id"] = creds[0]
        db_row = db.execute(VulnerabilityDiscovery.insert_returning(**row))
        db_row = db_row.all()[0]
        db.commit()

        resp = client.get(f"/submission/vds/{str(db_row.id)}", headers=auth_header)

        assert resp.status_code == 200

        resp = resp.json()

        assert resp["status"] == db_row.status.value
        assert resp["vd_uuid"] == str(db_row.id)
