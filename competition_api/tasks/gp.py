# pylint: disable=too-many-return-statements

import os

import whatthepatch
from sqlalchemy import func, select, update
from sqlalchemy_dlock.asyncio import create_async_sadlock
from structlog.stdlib import get_logger

from competition_api.audit import Auditor
from competition_api.audit.types import EventType, GPSubmissionFailReason
from competition_api.cp_workspace import BadReturnCode, CPWorkspace
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile
from competition_api.lib import peek
from competition_api.models.types import FeedbackStatus
from competition_api.tasks.lib import sanitizers_triggered_at

LOGGER = get_logger(__name__)


async def check_gp(
    _ctx, vds: VulnerabilityDiscovery, gp: GeneratedPatch, auditor: Auditor
):
    await LOGGER.ainfo("Testing GP %s", gp)

    # Make sure there is only one test going at a time for each (team id, cpv_uuid)
    async with db_session() as db, create_async_sadlock(
        db, f"{vds.team_id}-{vds.cpv_uuid}"
    ), CPWorkspace(vds.cp_name) as workspace:
        # ARQ uses an at-least-once job execution model
        if (
            await db.execute(
                select(GeneratedPatch.status).where(GeneratedPatch.id == gp.id)
            )
        ).fetchone()[0] != FeedbackStatus.PENDING:
            await LOGGER.awarning("GP %s was already tested.", gp.id)
            return

        # Check for duplicate
        submissions_for_cpv_uuid = (
            await db.execute(
                select(
                    func.count(GeneratedPatch.id)  # pylint: disable=not-callable
                ).where(
                    GeneratedPatch.cpv_uuid
                    == gp.cpv_uuid,  # CPV UUIDs are globally unique
                    GeneratedPatch.id != gp.id,
                )
            )
        ).fetchone()

        if submissions_for_cpv_uuid[0] > 0:
            await auditor.emit(
                EventType.DUPLICATE_GP_SUBMISSION_FOR_CPV_UUID,
            )

        # Verify patch only modifies allowed extensions
        patchfile = Flatfile(contents_hash=gp.data_sha256)
        try:
            content = await patchfile.read()
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
            async with db_session() as db:
                await db.execute(
                    update(GeneratedPatch)
                    .where(GeneratedPatch.id == gp.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
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
                async with db_session() as db:
                    await db.execute(
                        update(GeneratedPatch)
                        .where(GeneratedPatch.id == gp.id)
                        .values(status=FeedbackStatus.NOT_ACCEPTED)
                    )
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
            async with db_session() as db:
                await db.execute(
                    update(GeneratedPatch)
                    .where(GeneratedPatch.id == gp.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
            return

        await auditor.emit(EventType.GP_PATCH_BUILT)

        # The rest of the failures are silent
        async with db_session() as db:
            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(status=FeedbackStatus.ACCEPTED)
            )

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
