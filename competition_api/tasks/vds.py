# pylint: disable=too-many-return-statements

from typing import Any
from uuid import uuid4

import git
from sqlalchemy import func, select, update
from sqlalchemy_dlock.asyncio import create_async_sadlock
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import Auditor
from competition_api.audit.types import (
    Disposition,
    EventType,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)
from competition_api.cp_workspace import BadReturnCode, CPWorkspace
from competition_api.db import VulnerabilityDiscovery, db_session
from competition_api.models.types import FeedbackStatus
from competition_api.tasks.lib import sanitizers_triggered_at

LOGGER = get_logger(__name__)


async def check_vds(_ctx, vds: VulnerabilityDiscovery, auditor: Auditor):
    await LOGGER.ainfo("Testing VDS %s", vds)

    # Make sure there is only one test going at a time for each (team id, commit hash)
    async with db_session() as db, create_async_sadlock(
        db, f"{vds.team_id}-{vds.pou_commit_sha1}"
    ), CPWorkspace(vds.cp_name, auditor) as workspace:
        # ARQ uses an at-least-once job execution model
        if (
            await db.execute(
                select(VulnerabilityDiscovery.status).where(
                    VulnerabilityDiscovery.id == vds.id
                )
            )
        ).fetchone()[0] != FeedbackStatus.PENDING:
            await LOGGER.awarning("VDS %s was already tested.", vds.id)
            return

        # Validate sanitizer exists in project.yaml
        if (sanitizer_str := workspace.sanitizer(vds.pou_sanitizer)) is None:
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.SANITIZER_NOT_FOUND,
            )
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(status=FeedbackStatus.NOT_ACCEPTED)
            )
            return

        if not workspace.cp.has(vds.pou_commit_sha1):
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.COMMIT_NOT_IN_REPO,
            )
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(status=FeedbackStatus.NOT_ACCEPTED)
            )
            return
        workspace.set_src_repo(vds.pou_commit_sha1)

        if workspace.cp.is_initial_commit(vds.pou_commit_sha1):
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.SUBMITTED_INITIAL_COMMIT,
            )
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(status=FeedbackStatus.NOT_ACCEPTED)
            )
            return

        source = workspace.cp.source_from_ref(vds.pou_commit_sha1)
        if source is None:
            # this should never happen
            # if cp.has(commit_sha) then commit_sha is in one of the sources
            raise RuntimeError("source was none but cp.has(commit_sha) was true")

        src_ref = workspace.cp.sources[source].get("ref", "main")

        # Validate sanitizer fires at HEAD & introducing commit and doesn't fire before
        fail_reasons: list[VDSubmissionFailReason] = []
        for fail_reason, commit, triggered_is_good in [
            (
                VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                src_ref,
                True,
            ),
            (
                VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                vds.pou_commit_sha1,
                True,
            ),
            (
                VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                f"{vds.pou_commit_sha1}~1",
                False,
            ),
        ]:
            await LOGGER.adebug("Building at %s", commit)
            workspace.checkout(commit)

            await workspace.build(source)

            try:
                sanitizers = await sanitizers_triggered_at(
                    workspace, vds.pov_data_sha256, vds.pov_harness
                )
            except git.exc.GitCommandError:
                await auditor.emit(
                    EventType.VD_SUBMISSION_INVALID,
                    reason=VDSubmissionInvalidReason.COMMIT_CHECKOUT_FAILED,
                )
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == vds.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
                return
            except BadReturnCode:
                await auditor.emit(
                    EventType.VD_SUBMISSION_FAIL,
                    reasons=[VDSubmissionFailReason.RUN_POV_FAILED],
                )
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == vds.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
                return

            triggered = vds.pou_sanitizer in sanitizers
            success = not triggered_is_good ^ triggered

            if not success:
                fail_reasons.append(fail_reason)

            await auditor.emit(
                EventType.VD_SANITIZER_RESULT,
                commit_sha=workspace.current_commit(),
                disposition=Disposition.GOOD if success else Disposition.BAD,
                expected_sanitizer=sanitizer_str,
                expected_sanitizer_triggered=triggered,
                sanitizers_triggered=[workspace.sanitizer(san) for san in sanitizers],
            )

        if v.get_bool("scoring.reject_duplicate_vds"):
            # Check if the competitor has already submitted a working VDS for this commit
            submissions_for_commit = (
                await db.execute(
                    select(
                        func.count(  # pylint: disable=not-callable
                            VulnerabilityDiscovery.id
                        )
                    ).where(
                        VulnerabilityDiscovery.pou_commit_sha1 == vds.pou_commit_sha1,
                        VulnerabilityDiscovery.team_id == vds.team_id,
                        VulnerabilityDiscovery.cpv_uuid.is_not(None),
                    )
                )
            ).fetchone()

            if submissions_for_commit[0] > 0:
                await auditor.emit(
                    EventType.VD_SUBMISSION_FAIL,
                    reasons=[VDSubmissionFailReason.DUPLICATE_COMMIT],
                )
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == vds.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
                return

        # TODO: "Intentional Vuln?" box is not fill-out-able

        # Return results & assign CPV UUID if successful
        results: dict[str, Any] = {
            "status": (
                FeedbackStatus.NOT_ACCEPTED if fail_reasons else FeedbackStatus.ACCEPTED
            )
        }

        if fail_reasons:
            await auditor.emit(EventType.VD_SUBMISSION_FAIL, reasons=fail_reasons)
        else:
            results["cpv_uuid"] = uuid4()
            await LOGGER.adebug("CPV UUID assigned: %s", results["cpv_uuid"])
            await auditor.emit(
                EventType.VD_SUBMISSION_SUCCESS, cpv_uuid=results["cpv_uuid"]
            )

        await db.execute(
            update(VulnerabilityDiscovery)
            .where(VulnerabilityDiscovery.id == vds.id)
            .values(**results)
        )
