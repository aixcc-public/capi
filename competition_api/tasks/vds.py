# pylint: disable=too-many-return-statements

from typing import Any
from uuid import UUID, uuid4

import git
from redis.asyncio import Redis
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import RedisAuditor, get_auditor
from competition_api.audit.types import (
    Disposition,
    EventType,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)
from competition_api.cp_workspace import BadReturnCode, CPWorkspace
from competition_api.db import VulnerabilityDiscovery
from competition_api.models.types import FeedbackStatus
from competition_api.tasks.lib import sanitizers_triggered_at
from competition_api.tasks.results import ResultType, report

LOGGER = get_logger(__name__)


async def check_vds(
    _,
    audit_context: dict[str, Any],
    log_context: dict[str, str],
    vds: VulnerabilityDiscovery,
    duplicate: bool,
):
    auditor = get_auditor(cls=RedisAuditor, **audit_context)
    clear_contextvars()
    bind_contextvars(**log_context)

    await LOGGER.ainfo("Testing VDS %s", vds)

    redis = Redis(**v.get("redis.kwargs"))

    async with CPWorkspace(vds.cp_name, auditor, str(vds.team_id), redis) as workspace:
        # Validate sanitizer exists in project.yaml
        if (sanitizer_str := workspace.sanitizer(vds.pou_sanitizer)) is None:
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.SANITIZER_NOT_FOUND,
            )
            await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
            return

        if not workspace.cp.has(vds.pou_commit_sha1):
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.COMMIT_NOT_IN_REPO,
            )
            await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
            return
        workspace.set_src_repo(vds.pou_commit_sha1)

        if workspace.cp.is_initial_commit(vds.pou_commit_sha1):
            await auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.SUBMITTED_INITIAL_COMMIT,
            )
            await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
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
                await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
                return
            except BadReturnCode:
                await auditor.emit(
                    EventType.VD_SUBMISSION_FAIL,
                    reasons=[VDSubmissionFailReason.RUN_POV_FAILED],
                )
                await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
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

        if v.get_bool("scoring.reject_duplicate_vds") and duplicate:
            await auditor.emit(
                EventType.VD_SUBMISSION_FAIL,
                reasons=[VDSubmissionFailReason.DUPLICATE_COMMIT],
            )
            await report(redis, ResultType.VDS, vds.id, FeedbackStatus.NOT_ACCEPTED)
            return

        # TODO: "Intentional Vuln?" box is not fill-out-able

        # Return results
        cpv_uuid: UUID | None = None
        if fail_reasons:
            await auditor.emit(EventType.VD_SUBMISSION_FAIL, reasons=fail_reasons)
        else:
            cpv_uuid = uuid4()
            await LOGGER.adebug("CPV UUID assigned: %s", cpv_uuid)
            await auditor.emit(EventType.VD_SUBMISSION_SUCCESS, cpv_uuid=cpv_uuid)

        await report(
            redis,
            ResultType.VDS,
            vds.id,
            FeedbackStatus.NOT_ACCEPTED if fail_reasons else FeedbackStatus.ACCEPTED,
            cpv_uuid=cpv_uuid,
        )
