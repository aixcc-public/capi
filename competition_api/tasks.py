import os
from typing import Any
from uuid import uuid4

import git
import whatthepatch
from sqlalchemy import func, select, update
from sqlalchemy_dlock.asyncio import create_async_sadlock
from structlog.stdlib import get_logger

from competition_api.audit import Auditor
from competition_api.audit.types import (
    Disposition,
    EventType,
    GPSubmissionFailReason,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)
from competition_api.cp_workspace import CPWorkspace
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile
from competition_api.lib import peek
from competition_api.models.types import FeedbackStatus

LOGGER = get_logger(__name__)


class TaskRunner:
    def __init__(self, cp_name: str, auditor: Auditor):
        self.auditor = auditor
        self.workspace = CPWorkspace(cp_name)

    async def _sanitizers_triggered_at(
        self,
        pov_data_sha256: str,
        harness: str,
    ):
        await LOGGER.adebug("Calling harness %s with POV blob", harness)
        return await self.workspace.check_sanitizers(pov_data_sha256, harness)
        # TODO: store logs as artifact

    async def test_vds(self, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing VDS %s", vds)

        async with db_session() as db:
            # Make sure there is only one test going at a time for each (team id, commit hash)
            async with create_async_sadlock(db, f"{vds.team_id}-{vds.pou_commit_sha1}"):
                await self.workspace.setup()

                # Validate sanitizer exists in project.yaml
                if (
                    sanitizer_str := self.workspace.sanitizer(vds.pou_sanitizer)
                ) is None:
                    await self.auditor.emit(
                        EventType.VD_SUBMISSION_INVALID,
                        reason=VDSubmissionInvalidReason.SANITIZER_NOT_FOUND,
                    )
                    await db.execute(
                        update(VulnerabilityDiscovery)
                        .where(VulnerabilityDiscovery.id == vds.id)
                        .values(status=FeedbackStatus.NOT_ACCEPTED)
                    )
                    return

                if not self.workspace.cp.has(vds.pou_commit_sha1):
                    await self.auditor.emit(
                        EventType.VD_SUBMISSION_INVALID,
                        reason=VDSubmissionInvalidReason.COMMIT_NOT_IN_REPO,
                    )
                    await db.execute(
                        update(VulnerabilityDiscovery)
                        .where(VulnerabilityDiscovery.id == vds.id)
                        .values(status=FeedbackStatus.NOT_ACCEPTED)
                    )
                    return
                self.workspace.set_src_repo(vds.pou_commit_sha1)

                if self.workspace.cp.is_initial_commit(vds.pou_commit_sha1):
                    await self.auditor.emit(
                        EventType.VD_SUBMISSION_INVALID,
                        reason=VDSubmissionInvalidReason.SUBMITTED_INITIAL_COMMIT,
                    )
                    await db.execute(
                        update(VulnerabilityDiscovery)
                        .where(VulnerabilityDiscovery.id == vds.id)
                        .values(status=FeedbackStatus.NOT_ACCEPTED)
                    )
                    return

                source = self.workspace.cp.source_from_ref(vds.pou_commit_sha1)
                src_ref = self.workspace.cp.sources[source].get("ref", "main")

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
                    self.workspace.checkout(commit)

                    await self.workspace.build(source)

                    try:
                        sanitizers = await self._sanitizers_triggered_at(
                            vds.pov_data_sha256, vds.pov_harness
                        )
                    except git.exc.GitCommandError:
                        await self.auditor.emit(
                            EventType.VD_SUBMISSION_INVALID,
                            reason=VDSubmissionInvalidReason.COMMIT_CHECKOUT_FAILED,
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

                    await self.auditor.emit(
                        EventType.VD_SANITIZER_RESULT,
                        commit_sha=self.workspace.current_commit(),
                        disposition=Disposition.GOOD if success else Disposition.BAD,
                        expected_sanitizer=sanitizer_str,
                        expected_sanitizer_triggered=triggered,
                        sanitizers_triggered=[
                            self.workspace.sanitizer(san) for san in sanitizers
                        ],
                    )

                # Check if the competitor has already submitted a working VDS
                submissions_for_commit = (
                    await db.execute(
                        select(
                            func.count(  # pylint: disable=not-callable
                                VulnerabilityDiscovery.id
                            )
                        ).where(
                            VulnerabilityDiscovery.pou_commit_sha1
                            == vds.pou_commit_sha1,
                            VulnerabilityDiscovery.team_id == vds.team_id,
                            VulnerabilityDiscovery.cpv_uuid.is_not(None),
                        )
                    )
                ).fetchone()

                if submissions_for_commit[0] > 0:
                    await self.auditor.emit(
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
                        FeedbackStatus.NOT_ACCEPTED
                        if fail_reasons
                        else FeedbackStatus.ACCEPTED
                    )
                }

                if fail_reasons:
                    await self.auditor.emit(
                        EventType.VD_SUBMISSION_FAIL, reasons=fail_reasons
                    )
                else:
                    results["cpv_uuid"] = uuid4()
                    await LOGGER.adebug("CPV UUID assigned: %s", results["cpv_uuid"])
                    await self.auditor.emit(
                        EventType.VD_SUBMISSION_SUCCESS, cpv_uuid=results["cpv_uuid"]
                    )

                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == vds.id)
                    .values(**results)
                )

    async def test_gp(self, gp: GeneratedPatch, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing GP %s", gp)

        # Check for duplicate
        async with db_session() as db:
            submissions_for_cpv_uuid = (
                await db.execute(
                    select(
                        func.count(GeneratedPatch.id)  # pylint: disable=not-callable
                    ).where(
                        GeneratedPatch.cpv_uuid == gp.cpv_uuid,
                        GeneratedPatch.id != gp.id,
                    )
                )
            ).fetchone()

            if submissions_for_cpv_uuid[0] > 0:
                await self.auditor.emit(
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
            await self.auditor.emit(
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
                await self.auditor.emit(
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

        await self.workspace.setup()

        # Build with patch
        # TODO: Can't differentiate apply failure & build failure from outside ./runsh
        await LOGGER.adebug("Building GP with patch")

        ref = self.workspace.cp.head_ref_from_ref(vds.pou_commit_sha1)
        if ref is None:
            # Should never happen; we've already validated this commit is part of the CP
            raise ValueError(
                "VDS passed tests, but by the time we tested the GP the VDS's commit "
                "was not part of the CP"
            )

        self.workspace.set_src_repo(vds.pou_commit_sha1)
        self.workspace.checkout(ref)
        source = self.workspace.cp.source_from_ref(vds.pou_commit_sha1)
        result = await self.workspace.build(source, patch_sha256=gp.data_sha256)

        if not result:
            await self.auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.PATCH_DID_NOT_APPLY,
            )
            async with db_session() as db:
                await db.execute(
                    update(GeneratedPatch)
                    .where(GeneratedPatch.id == gp.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
            return

        await self.auditor.emit(EventType.GP_PATCH_BUILT)

        # The rest of the failures are silent
        async with db_session() as db:
            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(status=FeedbackStatus.ACCEPTED)
            )

        # Run functional tests
        result = await self.workspace.run_functional_tests()
        if not result:
            await self.auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.FUNCTIONAL_TESTS_FAILED,
            )
            return

        await self.auditor.emit(EventType.GP_FUNCTIONAL_TESTS_PASS)

        # Check if sanitizers fire
        triggered = vds.pou_sanitizer in await self._sanitizers_triggered_at(
            vds.pov_data_sha256, vds.pov_harness
        )

        if triggered:
            await self.auditor.emit(
                EventType.GP_SUBMISSION_FAIL,
                reason=GPSubmissionFailReason.SANITIZER_FIRED_AFTER_PATCH,
            )
            return

        await self.auditor.emit(EventType.GP_SANITIZER_DID_NOT_FIRE)

        # TODO: "Intentional Vuln?" box is not fill-out-able
        # TODO: Private PoV suite?
        # TODO: mark for manual review

        await self.auditor.emit(EventType.GP_SUBMISSION_SUCCESS)
