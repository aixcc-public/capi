# pylint: disable=unused-argument
# mypy: disable-error-code=attr-defined
import os
from pathlib import Path
from typing import Iterator
from unittest import mock
from uuid import UUID, uuid4

import pytest
import redis.asyncio as redis
from git import Repo
from sqlalchemy import insert, select, update

from competition_api.audit.types import (
    EventType,
    GPSubmissionFailReason,
    VDSubmissionFailReason,
    VDSubmissionInvalidReason,
)
from competition_api.db import GeneratedPatch, VulnerabilityDiscovery, db_session
from competition_api.flatfile import Flatfile, StorageType
from competition_api.models.types import FeedbackStatus
from competition_api.tasks.gp import check_gp
from competition_api.tasks.results import ResultType
from competition_api.tasks.vds import check_vds
from tests.lib.patch import build_patch

from .lib.auditor import mock_get_auditor


def build_mock_report(
    exp_result_type: ResultType, exp_row_id: UUID, exp_feedback_status: FeedbackStatus
):
    async def report(
        redis_: redis.Redis,
        result_type: ResultType,
        row_id: UUID,
        feedback_status: FeedbackStatus,
        cpv_uuid: UUID | None = None,
    ):
        assert redis_
        assert result_type == exp_result_type
        assert row_id == exp_row_id
        assert feedback_status == exp_feedback_status

        if result_type == ResultType.VDS and feedback_status == FeedbackStatus.ACCEPTED:
            assert cpv_uuid

    return report


def build_mock_run(
    pov_blob,
    pov_harness,
    source,
    gp_patch=None,
    sanitizer: Iterator | None = None,
    patch_returncode=0,
    tests_returncode=0,
    pov_returncode=0,
    container_name="",
    raises_timeout=None,
):
    raises_timeout = raises_timeout or []

    def mock_run(func, *args, cwd=None, stdin=None, env=None, timeout=3600):

        if func == "./run.sh":
            assert args[0:2] == (
                "-x",
                "-v",
            ), f"./run.sh was not called with -x and -v: got {args[0:2]}"
            args = args[2:]

            if args[0] in raises_timeout:
                raise TimeoutError

            if args[0] == "build":
                if gp_patch:
                    _, patch_filename, context = args
                    assert os.path.isfile(patch_filename), "Patch was not a file"
                    with open(patch_filename, "rb") as patch_file:
                        assert (
                            patch_file.read() == gp_patch
                        ), "Patch content did not match"
                    assert (
                        context == source
                    ), f"context was {context}, expected {source}"
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

                return (pov_returncode, "".encode("utf8"), "".encode("utf8"))

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
        elif func == "rm":
            assert args[0] == "-rf"
            assert args[1].startswith("/tmp")
            return (0, "".encode("utf8"), "".encode("utf8"))
        else:
            assert False, f"mock_run does not support {func}"

    return mock_run


class TestTestVDS:
    @staticmethod
    @pytest.mark.parametrize(
        "expected_event_type,fail_reason,sanitizer_fires,source,raises_timeout",
        [
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT],
                [True, True, True],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_SUCCESS,
                None,
                [True, True, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_SUCCESS,
                None,
                [True, True, False],
                "secondary/nested-folder",
                [],
            ),
            (
                EventType.VD_SUBMISSION_SUCCESS,
                None,
                [True, True, False],
                "tertiary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT],
                [True, False, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD],
                [False, True, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [False, False, True],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [False, True, True],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                    VDSubmissionFailReason.SANITIZER_FIRED_BEFORE_COMMIT,
                ],
                [True, False, True],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_HEAD,
                    VDSubmissionFailReason.SANITIZER_DID_NOT_FIRE_AT_COMMIT,
                ],
                [False, False, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_INVALID,
                VDSubmissionInvalidReason.SUBMITTED_INITIAL_COMMIT,
                [True, True, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.RUN_POV_FAILED],
                [True, True, False],
                "primary",
                [],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.RUN_POV_FAILED],
                [True, True, False],
                "primary",
                ["build"],
            ),
            (
                EventType.VD_SUBMISSION_FAIL,
                [VDSubmissionFailReason.RUN_POV_FAILED],
                [True, True, False],
                "primary",
                ["run_pov"],
            ),
        ],
    )
    async def test_check_vds(
        fake_vds,
        fake_cp,
        creds,
        test_project_yaml,
        repo,
        expected_event_type,
        fail_reason,
        sanitizer_fires,
        source,
        raises_timeout,
        auditor,
        container_name,
        container_sas,
    ):
        fail_test = expected_event_type == EventType.VD_SUBMISSION_FAIL
        invalid_test = expected_event_type == EventType.VD_SUBMISSION_INVALID

        src_repo = Repo(Path(repo.working_dir) / "src" / source)

        target_commit = src_repo.head.commit.hexsha
        if fail_reason == VDSubmissionInvalidReason.SUBMITTED_INITIAL_COMMIT:
            target_commit = [c for c in src_repo.iter_commits() if not c.parents][
                0
            ].hexsha

        async with db_session() as db:
            # make sure the commit sha we want to check out is in the repo
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_vds["id"])
                .values(pou_commit_sha1=target_commit.upper())
            )
            vds = (
                await db.execute(
                    select(VulnerabilityDiscovery).where(
                        VulnerabilityDiscovery.id == fake_vds["id"]
                    )
                )
            ).fetchone()[0]

        san = test_project_yaml["sanitizers"][fake_vds["pou_sanitizer"]]

        pov_data = await Flatfile(
            container_name, contents_hash=fake_vds["pov_data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_vds["pov_harness"]]["name"],
                source,
                sanitizer=(
                    san if fires else ""
                    for fires, san in zip(sanitizer_fires, [san, san, san])
                ),
                container_name=test_project_yaml["docker_image"],
                pov_returncode=(
                    1 if fail_reason == [VDSubmissionFailReason.RUN_POV_FAILED] else 0
                ),
                raises_timeout=raises_timeout,
            ),
        ), mock.patch(
            "competition_api.cp_workspace.CPWorkspace.checkout"
        ) as mock_checkout, mock.patch(
            "competition_api.tasks.vds.get_auditor", mock_get_auditor(auditor)
        ), mock.patch(
            "competition_api.tasks.vds.report",
            build_mock_report(
                ResultType.VDS,
                vds.id,
                (
                    FeedbackStatus.ACCEPTED
                    if not fail_test and not invalid_test
                    else FeedbackStatus.NOT_ACCEPTED
                ),
            ),
        ):
            await check_vds(
                None,
                {
                    "team_id": creds[0],
                    "vd_uuid": fake_vds["id"],
                    "cp_name": fake_vds["cp_name"],
                },
                {},
                vds,
                False,
                container_name,
                container_sas,
            )
            if (
                not invalid_test
                and fail_reason != [VDSubmissionFailReason.RUN_POV_FAILED]
                and not raises_timeout
            ):
                mock_checkout.assert_has_calls(
                    [
                        mock.call(
                            test_project_yaml["cp_sources"][source].get("ref", "main")
                        ),
                        mock.call(target_commit.upper()),
                        mock.call(f"{target_commit}~1".upper()),
                    ]
                )

        if raises_timeout:
            event = auditor.get_events(EventType.TIMEOUT)
            assert event

        event = auditor.get_events(expected_event_type)
        assert event
        event = event[0]

        if fail_test:
            assert event.reasons == fail_reason
        elif invalid_test:
            assert event.reason == fail_reason

        sanitizer_results = auditor.get_events(EventType.VD_SANITIZER_RESULT)
        assert len(sanitizer_results) == 0 if invalid_test else 3
        for fires, result in zip(sanitizer_fires, sanitizer_results):
            assert result.expected_sanitizer_triggered == fires

    @staticmethod
    @pytest.mark.parametrize(
        "existing_success,source",
        [
            (True, "primary"),
            (True, "secondary/nested-folder"),
            (True, "tertiary"),
            (False, "primary"),
            (False, "secondary/nested-folder"),
            (False, "tertiary"),
        ],
    )
    async def test_check_vds_duplicate(
        fake_vds,
        fake_vds_dict,
        fake_cp,
        creds,
        test_project_yaml,
        repo,
        existing_success,
        source,
        auditor,
        container_name,
        container_sas,
    ):
        src_repo = Repo(Path(repo.working_dir) / "src" / source)
        async with db_session() as db:
            commit_sha = src_repo.head.commit.hexsha

            existing_vds = {**fake_vds_dict}
            existing_vds["pou_commit_sha1"] = commit_sha
            if existing_success:
                existing_vds["status"] = FeedbackStatus.ACCEPTED
                existing_vds["cpv_uuid"] = str(uuid4())

            await db.execute(insert(VulnerabilityDiscovery).values(**existing_vds))
            vds = (
                await db.execute(
                    update(VulnerabilityDiscovery)
                    .where(VulnerabilityDiscovery.id == fake_vds["id"])
                    .values(pou_commit_sha1=commit_sha)
                    .returning(VulnerabilityDiscovery)
                )
            ).fetchone()[0]

        san = test_project_yaml["sanitizers"][fake_vds["pou_sanitizer"]]

        pov_data = await Flatfile(
            container_name, contents_hash=fake_vds["pov_data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_vds["pov_harness"]]["name"],
                source,
                sanitizer=(san for san in [san, san, ""]),
                container_name=test_project_yaml["docker_image"],
            ),
        ), mock.patch(
            "competition_api.tasks.vds.get_auditor", mock_get_auditor(auditor)
        ), mock.patch(
            "competition_api.tasks.vds.report",
            build_mock_report(
                ResultType.VDS,
                vds.id,
                (
                    FeedbackStatus.NOT_ACCEPTED
                    if existing_success
                    else FeedbackStatus.ACCEPTED
                ),
            ),
        ):
            await check_vds(
                None,
                {
                    "team_id": creds[0],
                    "vd_uuid": fake_vds["id"],
                    "cp_name": fake_vds["cp_name"],
                },
                {},
                vds,
                existing_success,
                container_name,
                container_sas,
            )

        event = auditor.get_events(EventType.VD_SUBMISSION_FAIL)

        if existing_success:
            assert event
            event = event[0]

            assert event.reasons == [VDSubmissionFailReason.DUPLICATE_COMMIT]
        else:
            assert not event


class TestTestGP:
    @staticmethod
    @pytest.mark.parametrize(
        (
            "patch_builds,functional_tests_pass,sanitizer_does_not_fire,"
            "pov_works,source,raises_timeout"
        ),
        [
            (True, True, True, True, "primary", []),
            (True, True, True, True, "secondary/nested-folder", []),
            (True, True, True, True, "tertiary", []),
            (True, True, False, True, "primary", []),
            (True, False, True, True, "primary", []),
            (True, False, False, True, "primary", []),
            (False, True, True, True, "primary", []),
            (False, True, False, True, "primary", []),
            (False, False, True, True, "primary", []),
            (False, False, False, True, "primary", []),
            (True, True, True, False, "primary", []),
            (True, True, True, False, "secondary/nested-folder", []),
            (True, True, True, False, "tertiary", []),
            (True, True, False, False, "primary", []),
            (True, False, True, False, "primary", []),
            (True, False, False, False, "primary", []),
            (False, True, True, False, "primary", []),
            (False, True, False, False, "primary", []),
            (False, False, True, False, "primary", []),
            (False, False, False, False, "primary", []),
            (True, False, True, True, "primary", ["run_tests"]),
            (False, True, True, True, "primary", ["build"]),
        ],
    )
    async def test_check_gp(
        fake_cp,
        fake_accepted_vds,
        fake_gp,
        repo,
        patch_builds,
        functional_tests_pass,
        sanitizer_does_not_fire,
        pov_works,
        source,
        test_project_yaml,
        creds,
        raises_timeout,
        auditor,
        container_name,
        container_sas,
    ):
        src_repo = Repo(Path(repo.working_dir) / "src" / source)
        async with db_session() as db:
            # make sure the commit sha we want to check out is in the repo
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_accepted_vds["id"])
                .values(pou_commit_sha1=src_repo.head.commit.hexsha)
            )

            gp = (
                await db.execute(
                    select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
                )
            ).fetchone()[0]

            vds = (
                await db.execute(
                    select(VulnerabilityDiscovery).where(
                        VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                    )
                )
            ).fetchone()[0]

        san = (
            ""
            if sanitizer_does_not_fire
            else test_project_yaml["sanitizers"][fake_accepted_vds["pou_sanitizer"]]
        )

        pov_data = await Flatfile(
            container_name, contents_hash=fake_accepted_vds["pov_data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)
        patch = await Flatfile(
            container_name, contents_hash=fake_gp["data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                source,
                gp_patch=patch,
                sanitizer=(san for san in [san, san, ""]),
                patch_returncode=0 if patch_builds else 1,
                tests_returncode=0 if functional_tests_pass else 1,
                pov_returncode=0 if pov_works else 1,
                container_name=test_project_yaml["docker_image"],
                raises_timeout=raises_timeout,
            ),
        ), mock.patch(
            "competition_api.tasks.gp.get_auditor", mock_get_auditor(auditor)
        ), mock.patch(
            "competition_api.tasks.gp.report",
            build_mock_report(
                ResultType.GP,
                gp.id,
                (
                    FeedbackStatus.NOT_ACCEPTED
                    if not patch_builds
                    else FeedbackStatus.ACCEPTED
                ),
            ),
        ):
            await check_gp(
                None,
                {
                    "team_id": creds[0],
                    "vd_uuid": fake_accepted_vds["id"],
                    "cp_name": fake_accepted_vds["cp_name"],
                    "gp_uuid": fake_gp["id"],
                    "cpv_uuid": fake_accepted_vds["cpv_uuid"],
                },
                {},
                vds,
                gp,
                False,
                container_name,
                container_sas,
            )

        if patch_builds:
            assert auditor.get_events(EventType.GP_PATCH_BUILT)
        else:
            if "build" in raises_timeout:
                assert auditor.get_events(EventType.TIMEOUT)
            assert not auditor.get_events(EventType.GP_PATCH_BUILT)
            fail = auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.PATCH_FAILED_APPLY_OR_BUILD
            return

        if functional_tests_pass:
            assert auditor.get_events(EventType.GP_FUNCTIONAL_TESTS_PASS)
        else:
            if "run_tests" in raises_timeout:
                assert auditor.get_events(EventType.TIMEOUT)
            assert not auditor.get_events(EventType.GP_FUNCTIONAL_TESTS_PASS)
            fail = auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.FUNCTIONAL_TESTS_FAILED
            return

        if pov_works:
            if sanitizer_does_not_fire:
                assert auditor.get_events(EventType.GP_SANITIZER_DID_NOT_FIRE)
            else:
                assert not auditor.get_events(EventType.GP_SANITIZER_DID_NOT_FIRE)
                fail = auditor.get_events(EventType.GP_SUBMISSION_FAIL)
                assert fail
                assert (
                    fail[0].reason == GPSubmissionFailReason.SANITIZER_FIRED_AFTER_PATCH
                )
                return
        else:
            assert not auditor.get_events(EventType.GP_SANITIZER_DID_NOT_FIRE)
            fail = auditor.get_events(EventType.GP_SUBMISSION_FAIL)
            assert fail
            assert fail[0].reason == GPSubmissionFailReason.RUN_POV_FAILED
            return

        assert auditor.get_events(EventType.GP_SUBMISSION_SUCCESS)

    @staticmethod
    @pytest.mark.parametrize(
        "source", ["primary", "secondary/nested-folder", "tertiary"]
    )
    async def test_check_gp_duplicate(
        fake_cp,
        fake_accepted_vds,
        fake_gp_dict,
        fake_gp,
        repo,
        test_project_yaml,
        creds,
        source,
        auditor,
        container_name,
        container_sas,
    ):
        patch_sha256 = fake_gp["data_sha256"]
        src_repo = Repo(Path(repo.working_dir) / "src" / source)
        async with db_session() as db:
            # make sure the commit sha we want to check out is in the repo
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_accepted_vds["id"])
                .values(pou_commit_sha1=src_repo.head.commit.hexsha)
            )
            await db.execute(insert(GeneratedPatch).values(**fake_gp_dict))

            gp = (
                await db.execute(
                    select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
                )
            ).fetchone()[0]

            vds = (
                await db.execute(
                    select(VulnerabilityDiscovery).where(
                        VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                    )
                )
            ).fetchone()[0]

        san = test_project_yaml["sanitizers"][fake_accepted_vds["pou_sanitizer"]]

        pov_data = await Flatfile(
            container_name, contents_hash=fake_accepted_vds["pov_data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)
        patch = await Flatfile(container_name, contents_hash=patch_sha256).read(
            from_=StorageType.AZUREBLOB
        )

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                source,
                gp_patch=patch,
                sanitizer=(san for san in [san, san, ""]),
                patch_returncode=0,
                tests_returncode=0,
                container_name=test_project_yaml["docker_image"],
            ),
        ), mock.patch(
            "competition_api.tasks.gp.get_auditor", mock_get_auditor(auditor)
        ), mock.patch(
            "competition_api.tasks.gp.report",
            build_mock_report(
                ResultType.GP,
                gp.id,
                # We don't tell the user about this type of failure
                FeedbackStatus.ACCEPTED,
            ),
        ):
            await check_gp(
                None,
                {
                    "team_id": creds[0],
                    "vd_uuid": fake_accepted_vds["id"],
                    "cp_name": fake_accepted_vds["cp_name"],
                    "gp_uuid": fake_gp["id"],
                    "cpv_uuid": fake_accepted_vds["cpv_uuid"],
                },
                {},
                vds,
                gp,
                True,
                container_name,
                container_sas,
            )

        dupe = auditor.get_events(EventType.DUPLICATE_GP_SUBMISSION_FOR_CPV_UUID)
        assert dupe

    @staticmethod
    @pytest.mark.parametrize(
        "fail_reason,patch_filename,source",
        [
            (
                GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION,
                "Makefile",
                "primary",
            ),
            (
                GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION,
                "test.py",
                "primary",
            ),
            (
                GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION,
                "whatsit.sh",
                "primary",
            ),
            (GPSubmissionFailReason.MALFORMED_PATCH_FILE, None, "primary"),
        ],
    )
    async def test_check_gp_fail(
        fake_cp,
        fake_accepted_vds,
        fake_gp_dict,
        fake_gp,
        repo,
        test_project_yaml,
        creds,
        fail_reason,
        patch_filename,
        source,
        auditor,
        container_name,
        container_sas,
    ):
        patch_sha256 = fake_gp["data_sha256"]
        src_repo = Repo(Path(repo.working_dir) / "src" / source)
        async with db_session() as db:
            # make sure the commit sha we want to check out is in the repo
            await db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_accepted_vds["id"])
                .values(pou_commit_sha1=src_repo.head.commit.hexsha)
            )
            if fail_reason in [
                GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION,
                GPSubmissionFailReason.MALFORMED_PATCH_FILE,
            ]:
                patch_content = (
                    build_patch(file=patch_filename)
                    if fail_reason
                    == GPSubmissionFailReason.PATCHED_DISALLOWED_FILE_EXTENSION
                    else "this\nis\nnot a patch\nfile"
                )
                blob = Flatfile(container_name, contents=patch_content.encode("utf8"))
                await blob.write(to=StorageType.AZUREBLOB)
                await db.execute(update(GeneratedPatch).values(data_sha256=blob.sha256))
                patch_sha256 = blob.sha256

            gp = (
                await db.execute(
                    select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
                )
            ).fetchone()[0]

            vds = (
                await db.execute(
                    select(VulnerabilityDiscovery).where(
                        VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                    )
                )
            ).fetchone()[0]

        san = test_project_yaml["sanitizers"][fake_accepted_vds["pou_sanitizer"]]

        pov_data = await Flatfile(
            container_name, contents_hash=fake_accepted_vds["pov_data_sha256"]
        ).read(from_=StorageType.AZUREBLOB)
        patch = await Flatfile(container_name, contents_hash=patch_sha256).read(
            from_=StorageType.AZUREBLOB
        )

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                pov_data,
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                source,
                gp_patch=patch,
                sanitizer=(san for san in [san, san, ""]),
                patch_returncode=0,
                tests_returncode=0,
                container_name=test_project_yaml["docker_image"],
            ),
        ), mock.patch(
            "competition_api.tasks.gp.get_auditor", mock_get_auditor(auditor)
        ), mock.patch(
            "competition_api.tasks.gp.report",
            build_mock_report(
                ResultType.GP,
                gp.id,
                FeedbackStatus.NOT_ACCEPTED,
            ),
        ):
            await check_gp(
                None,
                {
                    "team_id": creds[0],
                    "vd_uuid": fake_accepted_vds["id"],
                    "cp_name": fake_accepted_vds["cp_name"],
                    "gp_uuid": fake_gp["id"],
                    "cpv_uuid": fake_accepted_vds["cpv_uuid"],
                },
                {},
                vds,
                gp,
                False,
                container_name,
                container_sas,
            )

        fail = auditor.get_events(EventType.GP_SUBMISSION_FAIL)
        assert fail
        assert fail[0].reason == fail_reason
