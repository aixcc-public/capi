from datetime import datetime
from unittest import mock

import pytest

from competition_api.audit.types import EventType


class TestAudit:
    @staticmethod
    @pytest.mark.parametrize(
        "url,event,admin,authenticated",
        [
            ("/audit/start/", EventType.COMPETITION_START, True, True),
            ("/audit/stop/", EventType.COMPETITION_STOP, True, True),
            ("/audit/start/", EventType.COMPETITION_START, False, True),
            ("/audit/stop/", EventType.COMPETITION_STOP, False, True),
            ("/audit/start/", EventType.COMPETITION_START, False, False),
            ("/audit/stop/", EventType.COMPETITION_STOP, False, False),
        ],
    )
    def test_post_audit(
        client,
        mock_get_auditor,
        auditor,
        admin_auth_header,
        auth_header,
        url,
        event,
        admin,
        authenticated,
    ):
        timestamp = datetime.now()
        with mock.patch(
            "competition_api.endpoints.audit._router.get_auditor", mock_get_auditor
        ):
            resp = client.post(
                url,
                headers=(
                    (admin_auth_header if admin else auth_header)
                    if authenticated
                    else None
                ),
                json={"timestamp": timestamp.isoformat()},
            )

        if authenticated and admin:
            assert resp.status_code == 200

            audit_event = auditor.get_events(event)
            assert len(audit_event) == 1
            audit_event = audit_event[0]

            assert audit_event.timestamp == timestamp
        elif authenticated:
            assert resp.status_code == 403
            assert not auditor.events
        else:
            assert resp.status_code == 401
            assert not auditor.events
