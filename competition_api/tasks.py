from typing import Any
from uuid import uuid4

import git
from sqlalchemy import update
from structlog.stdlib import get_logger
from vyper import v

from competition_api.cp_workspace import CPWorkspace
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.models.types import FeedbackStatus

LOGGER = get_logger(__name__)


class TaskRunner:
    def __init__(self, cp_name: str):
        self.workspace = CPWorkspace(v.get(f"cp_targets.{cp_name}.url"))

    def _checkout(self, commit_sha: str):
        LOGGER.debug("Checking out %s", commit_sha)
        updates: dict[str, Any] = {}
        try:
            self.workspace.checkout(commit_sha)
            updates["commit_sha_checked_out"] = True
        except git.exc.GitCommandError:
            LOGGER.warning("Commit checkout failed")
            updates["commit_sha_checked_out"] = False
            updates["status"] = FeedbackStatus.NOT_ACCEPTED

        return updates

    async def _triggers_sanitizer(
        self, pov_data: bytes, harness: str, expected_sanitizer: str
    ):
        await LOGGER.adebug("Calling harness %s with POV blob", harness)
        sanitizers_triggered = await self.workspace.check_sanitizers(pov_data, harness)
        await LOGGER.adebug("Sanitizers triggered: %s", sanitizers_triggered)
        return expected_sanitizer in sanitizers_triggered

    async def test_vds(self, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing VDS %s", vds)

        await self.workspace.setup()

        checkout_updates = self._checkout(vds.pou_commit_sha1)

        async with db_session() as db:
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(**checkout_updates)
            )

            if not checkout_updates["commit_sha_checked_out"]:
                return

        await LOGGER.adebug("Building")
        await self.workspace.build()

        async with db_session() as db:
            result = await self._triggers_sanitizer(
                vds.pov_data, vds.pov_harness, vds.pou_sanitizer
            )
            await LOGGER.ainfo("VDS working: %s", result)

            await LOGGER.adebug("Updating VDS in database")

            sanitizer_updates: dict[str, Any] = {
                "status": (
                    FeedbackStatus.ACCEPTED if result else FeedbackStatus.NOT_ACCEPTED
                ),
                "sanitizer_fired": result,
            }

            if result:
                sanitizer_updates["cpv_uuid"] = uuid4()

            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == vds.id)
                .values(**sanitizer_updates)
            )

    async def test_gp(self, gp: GeneratedPatch, vds: VulnerabilityDiscovery):
        await LOGGER.ainfo("Testing GP %s", gp)

        await self.workspace.setup()

        # we know the VDS checkout works or we would not have gotten this far
        self._checkout(vds.pou_commit_sha1)

        await LOGGER.adebug("Building")
        async with db_session() as db:
            result = await self.workspace.build(patch=gp.data)
            patch_updates: dict[str, Any] = {"patch_applied": result}

            if not result:
                patch_updates["status"] = FeedbackStatus.NOT_ACCEPTED

            await db.execute(
                update(GeneratedPatch)
                .where(GeneratedPatch.id == gp.id)
                .values(**patch_updates)
            )

            await LOGGER.ainfo("Patch applied: %s", result)
            if not result:
                await LOGGER.awarning("Patch failed")
                return

            result = not await self._triggers_sanitizer(
                vds.pov_data, vds.pov_harness, vds.pou_sanitizer
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

            self._checkout("main")
            result = await self.workspace.run_functional_tests()
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
