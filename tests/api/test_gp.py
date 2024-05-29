# pylint: disable=too-many-arguments

import base64
from unittest import mock
from uuid import uuid4

import pytest
from sqlalchemy import select, update

from competition_api.audit.types import EventType, GPSubmissionInvalidReason
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery
from competition_api.models.types import FeedbackStatus


class TestGP:
    @staticmethod
    @pytest.mark.parametrize(
        "body,invalid_reason",
        [
            ({"data": "ZmFrZQo="}, None),
            ({"data": "ZmFrZQo="}, GPSubmissionInvalidReason.INVALID_VDS_ID),
            ({"data": "ZmFrZQo="}, GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM),
        ],
    )
    def test_post(
        db,
        client,
        body,
        invalid_reason,
        fake_accepted_vds,
        auth_header,
        mock_get_auditor,
        auditor,
    ):
        body["cpv_uuid"] = (
            str(uuid4())
            if invalid_reason == GPSubmissionInvalidReason.INVALID_VDS_ID
            else str(fake_accepted_vds["cpv_uuid"])
        )

        if invalid_reason == GPSubmissionInvalidReason.VDS_WAS_FROM_ANOTHER_TEAM:
            db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.cpv_uuid == fake_accepted_vds["cpv_uuid"])
                .values(team_id=uuid4())
            )
            db.commit()

        with mock.patch(
            "competition_api.endpoints.gp.gp.TaskRunner", autospec=True
        ), mock.patch("competition_api.endpoints.gp.gp.get_auditor", mock_get_auditor):
            resp = client.post("/submission/gp/", json=body, headers=auth_header)

        if invalid_reason:
            assert resp.status_code == 404
        else:
            assert resp.status_code == 200

        resp = resp.json()

        db_row = db.execute(select(GeneratedPatch)).fetchall()
        assert len(db_row) == 1
        db_row = db_row[0][0]

        data = base64.b64decode(body["data"])

        if not invalid_reason:
            assert resp["gp_uuid"] == str(db_row.id)
            assert resp["status"] == FeedbackStatus.PENDING.value
            assert resp["patch_size"] == len(data)
            assert str(db_row.cpv_uuid) == body["cpv_uuid"]
            assert db_row.data == data
            assert db_row.status == FeedbackStatus.PENDING
        else:
            assert not resp.get("gp_uuid")

        submission_evt = auditor.get_events(EventType.GP_SUBMISSION)
        assert submission_evt
        submission_evt = submission_evt[0]

        assert submission_evt.patch_b64 == body["data"]
        assert str(submission_evt.submitted_cpv_uuid) == body["cpv_uuid"]

        invalid_evt = auditor.get_events(EventType.GP_SUBMISSION_INVALID)
        if invalid_reason:
            assert invalid_evt
            invalid_evt = invalid_evt[0]
            assert invalid_evt.reason == invalid_reason
        else:
            assert not invalid_evt

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

    @staticmethod
    def test_get_other_team(db, client, fake_gp, auth_header):
        db.execute(
            update(VulnerabilityDiscovery)
            .where(VulnerabilityDiscovery.cpv_uuid == fake_gp["cpv_uuid"])
            .values(team_id=uuid4())
        )
        db.commit()

        resp = client.get(f"/submission/gp/{str(fake_gp['id'])}", headers=auth_header)

        assert resp.status_code == 404
