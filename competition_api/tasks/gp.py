# pylint: disable=too-many-return-statements
import os
from typing import Any

import whatthepatch
from redis.asyncio import Redis
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import RedisAuditor, get_auditor
from competition_api.audit.types import EventType, GPSubmissionFailReason
from competition_api.cp_workspace import BadReturnCode, CPWorkspace
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery
from competition_api.flatfile import Flatfile, StorageType
from competition_api.lib import peek
from competition_api.models.types import FeedbackStatus
from competition_api.tasks.lib import sanitizers_triggered_at
from competition_api.tasks.results import ResultType, report

LOGGER = get_logger(__name__)


async def check_gp(
    _,
    audit_context: dict[str, Any],
    log_context: dict[str, str],
    vds: VulnerabilityDiscovery,
    gp: GeneratedPatch,
    duplicate: bool,
):
    auditor = get_auditor(cls=RedisAuditor, **audit_context)
    clear_contextvars()
    bind_contextvars(**log_context)

    await LOGGER.ainfo("Testing GP %s", gp)

    redis = Redis(**v.get("redis.kwargs"))

    async with CPWorkspace(vds.cp_name, auditor, str(vds.team_id), redis) as workspace:
        if duplicate:
            await auditor.emit(
                EventType.DUPLICATE_GP_SUBMISSION_FOR_CPV_UUID,
            )

        # Verify patch only modifies allowed extensions
        patchfile = Flatfile(contents_hash=gp.data_sha256)
        try:
            content = await patchfile.read(from_=StorageType.AZUREBLOB)
            if content is None:
                raise ValueError("Patch file was empty")

            wtp_diffs = whatthepatch.parse_patch(content.decode("utf8"))
            if not (diffs := peek(wtp_diffs)):
                raise ValueError("No diffs in patch file")

        except Exception:  # pylint: disable=broad-exception-caught
            # Catch any exceptions utf-8 decoding or parsing
            await auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.MALFORMED_PATCH_FILE,
            )
            await report(redis, ResultType.GP, gp.id, FeedbackStatus.NOT_ACCEPTED)
            return

        for diff in diffs:
            if not diff.header:
                extension = "unparseable-header"
            else:
                _, extension = os.path.splitext(diff.header.old_path)
            if extension.lower() not in [".c", ".h", ".in", ".java"]:
                await auditor.emit(
                    EventType.GP_SUBMISSION_FAIL,
                    reason=GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION,
                )
                await report(redis, ResultType.GP, gp.id, FeedbackStatus.NOT_ACCEPTED)
                return

        # Build with patch
        await LOGGER.adebug("Building GP with patch")

        ref = workspace.cp.head_ref_from_ref(vds.pou_commit_sha1)
        if ref is None:
            # Should never happen; we've already validated this commit is part of the CP
            raise ValueError(
                "VDS passed tests, but by the time we tested the GP the VDS's commit "
                "was not part of the CP"
            )

        workspace.set_src_repo(vds.pou_commit_sha1)
        workspace.checkout(ref)

        source = workspace.cp.source_from_ref(vds.pou_commit_sha1)
        if source is None:
            # this should never happen. if cp.head_ref_from_ref() returned a value,
            # then commit_sha is in one of the sources
            raise RuntimeError(
                "source was none but cp.head_ref_from_ref() returned a ref"
            )

        result = await workspace.build(source, patch_sha256=gp.data_sha256)

        if not result:
            await auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.PATCH_FAILED_APPLY_OR_BUILD,
            )
            await report(redis, ResultType.GP, gp.id, FeedbackStatus.NOT_ACCEPTED)
            return

        await auditor.emit(EventType.GP_PATCH_BUILT)

        # The rest of the failures are silent
        await report(redis, ResultType.GP, gp.id, FeedbackStatus.ACCEPTED)

        # Run functional tests
        result = await workspace.run_functional_tests()
        if not result:
            await auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.FUNCTIONAL_TESTS_FAILED,
            )
            return

        await auditor.emit(EventType.GP_FUNCTIONAL_TESTS_PASS)

        # Check if sanitizers fire
        try:
            triggered = vds.pou_sanitizer in await sanitizers_triggered_at(
                workspace, vds.pov_data_sha256, vds.pov_harness
            )
        except BadReturnCode:
            # The POV ran successfully already, so this should never happen
            await auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.RUN_POV_FAILED,
            )
            return

        if triggered:
            await auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.SANITIZER_FIRED_AFTER_PATCH,
            )
            return

        await auditor.emit(EventType.GP_SANITIZER_DID_NOT_FIRE)

        # TODO: "Intentional Vuln?" box is not fill-out-able
        # TODO: Private PoV suite?
        # TODO: mark for manual review

        await auditor.emit(EventType.GP_SUBMISSION_SUCCESS)
