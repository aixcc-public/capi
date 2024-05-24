from typing import Any
from uuid import uuid4

import git
from sqlalchemy import func, select, update
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import Auditor
from competition_api.audit.types import (
    Disposition,
    EventType,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)
from competition_api.cp_workspace import CPWorkspace
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.models.types import FeedbackStatus

LOGGER = get_logger(__name__)


class TaskRunner:
    def __init__(self, cp_name: str, auditor: Auditor):
        self.auditor = auditor
        self.workspace = CPWorkspace(v.get(f"cp_targets.{cp_name}.url"))

    async def _sanitizers_triggered_at(
        self,
        pov_data: bytes,
        harness: str,
        commit_ref: str,
    ):

        self.workspace.checkout(commit_ref)
        await LOGGER.adebug("Calling harness %s with POV blob", harness)
        return await self.workspace.check_sanitizers(pov_data, harness)
        # TODO: store logs as artifact

    async def test_vds(self, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing VDS %s", vds)

        await self.workspace.setup()

        # Validate sanitizer exists in project.yaml
        if (sanitizer_str := self.workspace.sanitizer(vds.pou_sanitizer)) is None:
            await self.auditor.emit(
                EventType.VD_SUBMISSION_INVALID,
                reason=VDSubmissionInvalidReason.SANITIZER_NOT_FOUND,
            )
            async with db_session() as db:
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == vds.id)
                    .values(status=FeedbackStatus.NOT_ACCEPTED)
                )
                return

        # Validate sanitizer fires at HEAD & introducing commit and doesn't fire before
        fail_reasons: list[VDSubmissionFailReason] = []
        for fail_reason, commit, triggered_is_good in [
            (
                VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                "HEAD",
                True,
            ),  # TODO: HEAD may not work
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
            await self.workspace.build()

            try:
                sanitizers = await self._sanitizers_triggered_at(
                    vds.pov_data, vds.pov_harness, commit
                )
            except git.exc.GitCommandError:
                await self.auditor.emit(
                    EventType.VD_SUBMISSION_INVALID,
                    reason=VDSubmissionInvalidReason.COMMIT_CHECKOUT_FAILED,
                )
                async with db_session() as db:
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

        # Check for duplicate
        async with db_session() as db:
            submissions_for_commit = await db.execute(
                select(
                    func.count(  # pylint: disable=not-callable
                        VulnerabilityDiscovery.id
                    )
                ).where(VulnerabilityDiscovery.pou_commit_sha1 == vds.pou_commit_sha1)
            )
            submissions_for_commit = await submissions_for_commit.fetchone()

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
                FeedbackStatus.NOT_ACCEPTED if fail_reasons else FeedbackStatus.ACCEPTED
            )
        }

        if fail_reasons:
            await self.auditor.emit(EventType.VD_SUBMISSION_FAIL, reasons=fail_reasons)
        else:
            results["cpv_uuid"] = uuid4()
            await LOGGER.adebug("CPV UUID assigned: %s", results["cpv_uuid"])
            await self.auditor.emit(
                EventType.VD_SUBMISSION_SUCCESS, cpv_uuid=results["cpv_uuid"]
            )

        async with db_session() as db:
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(**results)
            )

    async def test_gp(self, gp: GeneratedPatch, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing GP %s", gp)

        await self.workspace.setup()

        self.workspace.checkout("HEAD")

        await LOGGER.adebug("Building")
        async with db_session() as db:
            result = await self.workspace.build(patch=gp.data)
            patch_updates: dict[str, Any] = {"patch_applied": result}

            if not result:
                patch_updates["status"] = FeedbackStatus.NOT_ACCEPTED

            # TODO: audit patch apply

            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(**patch_updates)
            )

            await LOGGER.ainfo("Patch applied: %s", result)
            if not result:
                await LOGGER.awarning("Patch failed")
                return

            result = not await self._sanitizers_triggered_at(
                vds.pov_data, vds.pov_harness, "HEAD"
            )
            sanitizer_updates: dict[str, Any] = {"sanitizer_did_not_fire": result}
            if not result:
                sanitizer_updates["status"] = FeedbackStatus.NOT_ACCEPTED

            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(**sanitizer_updates)
            )

            await LOGGER.ainfo("Sanitizer did not fire after patch: %s", result)
            if not result:
                await LOGGER.awarning("Sanitizer fired after patch")
                return

            # TODO: at this point the patch is ACCEPTED, but we have to audit this as a failure
            result = await self.workspace.run_functional_tests()

            # TODO: test PoV _after_ func tests, not before

            # TODO: "Intentional Vuln?" box is not fill-out-able

            # TODO: check duplicate

            await LOGGER.adebug("Updating GP in database")
            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(
                    status=(
                        FeedbackStatus.ACCEPTED
                        if result
                        else FeedbackStatus.NOT_ACCEPTED
                    ),
                    functional_tests_passed=result,
                )
            )
