# pylint: disable=too-many-arguments,too-many-locals,too-many-return-statements,unused-argument

import os
from typing import Iterator
from unittest import mock

import pytest
from git import Repo
from sqlalchemy import create_engine, insert, select, update
from sqlalchemy.orm import sessionmaker
from vyper import v

from competition_api.audit.types import (
    EventType,
    GPSubmissionFailReason,
    VDSubmissionFailReason,
)
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery
from competition_api.flatfile import Flatfile
from competition_api.models.types import FeedbackStatus
from competition_api.tasks import TaskRunner

from .lib.auditor import RecordingAuditor


def build_mock_setup(base_repo):
    cp_src_path = os.path.join(base_repo.working_dir, "src", "samples")
    src_repo = Repo(cp_src_path)

    async def mock_setup(self):
        self.src_repo = src_repo

    return mock_setup, src_repo


def build_mock_run(
    pov_blob,
    pov_harness,
    gp_patch=None,
    sanitizer: Iterator | None = None,
    patch_returncode=0,
    tests_returncode=0,
    container_name="",
):
    def mock_run(func, *args, cwd=None, stdin=None, env=None):
        if func == "./run.sh":
            if args[0] == "build":
                if gp_patch:
                    _, patch_filename, context = args
                    assert os.path.isfile(patch_filename), "Patch was not a file"
                    with open(patch_filename, "rb") as patch_file:
                        assert (
                            patch_file.read() == gp_patch
                        ), "Patch content did not match"
                    assert (
                        context == "samples"
                    ), f"context was {context}, expected samples"
                    return (patch_returncode, "".encode("utf8"), "".encode("utf8"))

                # make sure we're not trying to build a patch now
                assert len(args) == 1, f"Args too long: {args}"
                return (0, "".encode("utf8"), "".encode("utf8"))

            if args[0] == "run_pov":
                _, blob_filename, harness = args

                assert os.path.isfile(blob_filename), "Blob was not a file"
                with open(blob_filename, "rb") as blob_file:
                    assert blob_file.read() == pov_blob, "Blob content did not match"

                assert (
                    harness == pov_harness
                ), f"harness was {harness}, expected {pov_harness}"

                assert cwd
                output_dir = os.path.join(
                    cwd, "out", "output", "some-timestamp-run_pov"
                )
                os.makedirs(output_dir, exist_ok=True)

                with open(
                    os.path.join(output_dir, "stdout.log"), "w", encoding="utf8"
                ) as stdout_file:
                    stdout_file.write("")

                with open(
                    os.path.join(output_dir, "stderr.log"), "w", encoding="utf8"
                ) as stderr_file:
                    stderr_file.write(next(sanitizer) if sanitizer else "")

                return (0, "".encode("utf8"), "".encode("utf8"))

            if args[0] == "run_tests":
                assert len(args) == 1, f"Args too long: {args}"
                return (tests_returncode, "".encode("utf8"), "".encode("utf8"))

            assert False, f"run() was called for an unsupported case: {func} {args}"
        elif func == "make":
            return (0, "".encode("utf8"), "".encode("utf8"))
        elif func == "docker":
            if args[0] == "login":
                assert args[1:] == (
                    "ghcr.io",
                    "-u",
                    os.environ.get("GITHUB_USER", ""),
                    "--password-stdin",
                )
                assert stdin == os.environ.get("GITHUB_TOKEN", "")
                return (0, "".encode("utf8"), "".encode("utf8"))

            if args[0] == "pull":
                assert args[1:] == (container_name,)
                return (0, "".encode("utf8"), "".encode("utf8"))

            assert False, f"mock_run does not support docker {args}"

        else:
            assert False, f"mock_run does not support {func}"

    return mock_run


class TestTestVDS:
    @staticmethod
    @pytest.mark.parametrize(
        "expected_event_type,fail_reason,sanitizer_fires",
        [
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT],
                [True, True, True],
            ),
            (EventType.VD_SUBMISSION_SUCCESS, None, [True, True, False]),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT],
                [True, False, False],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD],
                [False, True, False],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [False, False, True],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [False, True, True],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [True, False, True],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                ],
                [False, False, False],
            ),
        ],
    )
    async def test_test_vds(
        fake_vds,
        fake_cp,
        creds,
        test_project_yaml,
        repo,
        expected_event_type,
        fail_reason,
        sanitizer_fires,
    ):
        engine = create_engine(v.get("database.url"))
        setup, src_repo = build_mock_setup(repo)
        with sessionmaker(engine, expire_on_commit=False)() as db:
            # make sure the commit sha we want to check out is in the repo
            db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_vds["id"])
                .values(pou_commit_sha1=src_repo.head.commit.hexsha)
            )
            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_vds["id"]
                )
            ).fetchone()[0]

            db.commit()

        auditor = RecordingAuditor(creds[0])
        auditor.push_context(vd_uuid=fake_vds["id"], cp_name=fake_vds["cp_name"])
        runner = TaskRunner(fake_cp, auditor)

        san = runner.workspace.project_yaml["sanitizers"][fake_vds["pou_sanitizer"]]

        pov_data = await Flatfile(contents_hash=fake_vds["pov_data_sha256"]).read()

        with mock.patch(
            "competition_api.cp_workspace.CPWorkspace.setup",
            setup,
        ), mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_vds["pov_harness"]]["name"],
                sanitizer=(
                    san if fires else ""
                    for fires, san in zip(sanitizer_fires, [san, san, san])
                ),
                container_name=test_project_yaml["docker_image"],
            ),
        ):
            await runner.test_vds(vds)

        event = runner.auditor.get_events(expected_event_type)
        assert event
        event = event[0]

        success_test = not expected_event_type == EventType.VD_SUBMISSION_FAIL

        if not success_test:
            assert event.reasons == fail_reason

        sanitizer_results = runner.auditor.get_events(EventType.VD_SANITIZER_RESULT)
        assert len(sanitizer_results) == 3
        for fires, result in zip(sanitizer_fires, sanitizer_results):
            assert result.expected_sanitizer_triggered == fires

        with sessionmaker(engine, expire_on_commit=False)() as db:
            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_vds["id"]
                )
            ).fetchone()[0]

            if success_test:
                assert vds.status == FeedbackStatus.ACCEPTED
                assert vds.cpv_uuid
            else:
                assert vds.status == FeedbackStatus.NOT_ACCEPTED
                assert vds.cpv_uuid is None

    @staticmethod
    async def test_test_vds_duplicate(
        fake_vds,
        fake_vds_dict,
        fake_cp,
        creds,
        test_project_yaml,
        repo,
    ):
        engine = create_engine(v.get("database.url"))
        setup, src_repo = build_mock_setup(repo)
        with sessionmaker(engine, expire_on_commit=False)() as db:
            commit_sha = src_repo.head.commit.hexsha

            db.execute(
                insert(VulnerabilityDiscovery).values(
                    **{**fake_vds_dict, "pou_commit_sha1": commit_sha}
                )
            )
            vds = list(
                db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == fake_vds["id"])
                    .values(pou_commit_sha1=commit_sha)
                    .returning(VulnerabilityDiscovery)
                )
            )[0][0]

            db.commit()

        auditor = RecordingAuditor(creds[0])
        auditor.push_context(vd_uuid=fake_vds["id"], cp_name=fake_vds["cp_name"])
        runner = TaskRunner(fake_cp, auditor)

        san = runner.workspace.project_yaml["sanitizers"][fake_vds["pou_sanitizer"]]

        pov_data = await Flatfile(contents_hash=fake_vds["pov_data_sha256"]).read()

        with mock.patch(
            "competition_api.cp_workspace.CPWorkspace.setup",
            setup,
        ), mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_vds["pov_harness"]]["name"],
                sanitizer=(san for san in [san, san, ""]),
                container_name=test_project_yaml["docker_image"],
            ),
        ):
            await runner.test_vds(vds)

        event = runner.auditor.get_events(EventType.VD_SUBMISSION_FAIL)
        assert event
        event = event[0]

        assert event.reasons == [VDSubmissionFailReason.DUPLICATE_COMMIT]

        with sessionmaker(engine, expire_on_commit=False)() as db:
            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_vds["id"]
                )
            ).fetchone()[0]

            assert vds.status == FeedbackStatus.NOT_ACCEPTED
            assert vds.cpv_uuid is None


class TestTestGP:
    @staticmethod
    @pytest.mark.parametrize(
        "patch_builds,functional_tests_pass,sanitizer_does_not_fire",
        [
            (True, True, True),
            (True, True, False),
            (True, False, True),
            (True, False, False),
            (False, True, True),
            (False, True, False),
            (False, False, True),
            (False, False, False),
        ],
    )
    async def test_test_gp(
        fake_cp,
        fake_accepted_vds,
        fake_gp,
        repo,
        patch_builds,
        functional_tests_pass,
        sanitizer_does_not_fire,
        test_project_yaml,
        creds,
    ):
        engine = create_engine(v.get("database.url"))
        setup, src_repo = build_mock_setup(repo)
        with sessionmaker(engine, expire_on_commit=False)() as db:
            # make sure the commit sha we want to check out is in the repo
            db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_accepted_vds["id"])
                .values(pou_commit_sha1=src_repo.head.commit.hexsha)
            )

            gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchone()[0]

            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                )
            ).fetchone()[0]

            db.commit()

        auditor = RecordingAuditor(creds[0])
        auditor.push_context(
            vd_uuid=fake_accepted_vds["id"],
            cp_name=fake_accepted_vds["cp_name"],
            gp_uuid=fake_gp["id"],
            cpv_uuid=fake_accepted_vds["cpv_uuid"],
        )
        runner = TaskRunner(fake_cp, auditor)

        san = (
            ""
            if sanitizer_does_not_fire
            else runner.workspace.project_yaml["sanitizers"][
                fake_accepted_vds["pou_sanitizer"]
            ]
        )

        pov_data = await Flatfile(
            contents_hash=fake_accepted_vds["pov_data_sha256"]
        ).read()
        patch = await Flatfile(contents_hash=fake_gp["data_sha256"]).read()

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                gp_patch=patch,
                sanitizer=(san for san in [san, san, ""]),
                patch_returncode=0 if patch_builds else 1,
                tests_returncode=0 if functional_tests_pass else 1,
                container_name=test_project_yaml["docker_image"],
            ),
        ), mock.patch(
            "competition_api.cp_workspace.CPWorkspace.setup",
            setup,
        ):
            await runner.test_gp(gp, vds)

        # TODO duplicate
        if patch_builds:
            assert runner.auditor.get_events(EventType.GP_PATCH_BUILT)
        else:
            assert not runner.auditor.get_events(EventType.GP_PATCH_BUILT)
            fail = runner.auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.PATCH_DID_NOT_APPLY
            return

        if functional_tests_pass:
            assert runner.auditor.get_events(EventType.GP_FUNCTIONAL_TESTS_PASS)
        else:
            assert not runner.auditor.get_events(EventType.GP_FUNCTIONAL_TESTS_PASS)
            fail = runner.auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.FUNCTIONAL_TESTS_FAILED
            return

        if sanitizer_does_not_fire:
            assert runner.auditor.get_events(EventType.GP_SANITIZER_DID_NOT_FIRE)
        else:
            assert not runner.auditor.get_events(EventType.GP_SANITIZER_DID_NOT_FIRE)
            fail = runner.auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.SANITIZER_FIRED_AFTER_PATCH
            return

        assert runner.auditor.get_events(EventType.GP_SUBMISSION_SUCCESS)

        with sessionmaker(engine, expire_on_commit=False)() as db:
            gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchone()[0]

            if all([patch_builds, functional_tests_pass, sanitizer_does_not_fire]):
                assert gp.status == FeedbackStatus.ACCEPTED
            else:
                assert gp.status == FeedbackStatus.NOT_ACCEPTED

    @staticmethod
    async def test_test_gp_duplicate(
        fake_cp,
        fake_accepted_vds,
        fake_gp_dict,
        fake_gp,
        repo,
        test_project_yaml,
        creds,
    ):
        engine = create_engine(v.get("database.url"))
        setup, _ = build_mock_setup(repo)
        with sessionmaker(engine, expire_on_commit=False)() as db:
            db.execute(insert(GeneratedPatch).values(**fake_gp_dict))

            gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchone()[0]

            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                )
            ).fetchone()[0]

            db.commit()

        auditor = RecordingAuditor(creds[0])
        auditor.push_context(
            vd_uuid=fake_accepted_vds["id"],
            cp_name=fake_accepted_vds["cp_name"],
            gp_uuid=fake_gp["id"],
            cpv_uuid=fake_accepted_vds["cpv_uuid"],
        )
        runner = TaskRunner(fake_cp, auditor)

        san = runner.workspace.project_yaml["sanitizers"][
            fake_accepted_vds["pou_sanitizer"]
        ]

        pov_data = await Flatfile(
            contents_hash=fake_accepted_vds["pov_data_sha256"]
        ).read()
        patch = await Flatfile(contents_hash=fake_gp["data_sha256"]).read()

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                gp_patch=patch,
                sanitizer=(san for san in [san, san, ""]),
                patch_returncode=0,
                tests_returncode=0,
                container_name=test_project_yaml["docker_image"],
            ),
        ), mock.patch(
            "competition_api.cp_workspace.CPWorkspace.setup",
            setup,
        ):
            await runner.test_gp(gp, vds)

        fail = runner.auditor.get_events(EventType.GP_SUBMISSION_FAIL)
        assert fail
        assert fail[0].reason == GPSubmissionFailReason.DUPLICATE_CPV_UUID

        with sessionmaker(engine, expire_on_commit=False)() as db:
            gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchone()[0]

            assert gp.status == FeedbackStatus.NOT_ACCEPTED
