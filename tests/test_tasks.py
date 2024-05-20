import os
from unittest import mock

import pytest
from sqlalchemy import create_engine, select, update
from sqlalchemy.orm import sessionmaker
from vyper import v

from competition_api.db import GeneratedPatch, VulnerabilityDiscovery
from competition_api.models.types import FeedbackStatus
from competition_api.tasks import TaskRunner


def build_mock_run(
    pov_blob,
    pov_harness,
    gp_patch=None,
    sanitizer=None,
    patch_returncode=0,
    tests_returncode=0,
    container_name="",
):  # pylint: disable=too-many-arguments,too-many-return-statements
    def mock_run(
        func, *args, cwd=None, stdin=None, env=None
    ):  # pylint: disable=unused-argument
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

                output_dir = os.path.join(
                    cwd, "out", "output", "some-timestamp-run_pov"
                )
                os.makedirs(output_dir)

                with open(
                    os.path.join(output_dir, "stdout.log"), "w", encoding="utf8"
                ) as stdout_file:
                    stdout_file.write("")

                with open(
                    os.path.join(output_dir, "stderr.log"), "w", encoding="utf8"
                ) as stderr_file:
                    stderr_file.write(sanitizer if sanitizer else "")

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
    @pytest.mark.parametrize("sanitizer_fires", [True, False])
    async def test_test_vds(
        fake_cp, fake_vds, repo, sanitizer_fires, test_project_yaml
    ):
        engine = create_engine(v.get("database.url"))
        with sessionmaker(engine)() as db:
            # make sure the commit sha we want to check out is in the repo
            db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_vds["id"])
                .values(pou_commit_sha1=repo.head.commit.hexsha)
            )

            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_vds["id"]
                )
            ).fetchall()[0][0]

            assert (
                vds.sanitizer_fired is None
            ), f"vds_sanitizer was {vds.sanitizer_fired} right after creation"

        runner = TaskRunner(fake_cp)

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                fake_vds["pov_data"],
                test_project_yaml["harnesses"][fake_vds["pov_harness"]]["name"],
                sanitizer=(
                    runner.workspace.project_yaml["sanitizers"][
                        fake_vds["pou_sanitizer"]
                    ]
                    if sanitizer_fires
                    else None
                ),
                container_name=test_project_yaml["docker_image"],
            ),
        ):
            await runner.test_vds(vds)

        with sessionmaker(engine)() as db:
            db_vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_vds["id"]
                )
            ).fetchall()[0][0]

            expected_status = (
                FeedbackStatus.ACCEPTED
                if sanitizer_fires
                else FeedbackStatus.NOT_ACCEPTED
            )
            assert (
                db_vds.status == expected_status
            ), f"status was {db_vds.status}, expected {expected_status}"
            assert db_vds.sanitizer_fired == sanitizer_fires, (
                f"sanitizer_fired was marked {db_vds.sanitizer_fired} but "
                f"sanitizer_fires was {sanitizer_fires}"
            )

            if sanitizer_fires:
                assert db_vds.cpv_uuid, "cpv_uuid was unset but sanitizer fired"
            else:
                assert (
                    db_vds.cpv_uuid is None
                ), "cpv_uuid was set but sanitizer did not fire"


class TestTestGP:
    @staticmethod
    @pytest.mark.parametrize(
        "patch_applies,sanitizer_does_not_fire,functional_tests_pass",
        [
            (True, True, True),
            (True, True, False),
            (True, False, True),
            (False, True, True),
            (True, False, False),
            (False, False, False),
            (False, True, False),
        ],
    )
    async def test_test_gp(
        fake_cp,
        fake_accepted_vds,
        fake_gp,
        repo,
        patch_applies,
        sanitizer_does_not_fire,
        functional_tests_pass,
        test_project_yaml,
    ):  # pylint: disable=too-many-arguments
        engine = create_engine(v.get("database.url"))
        with sessionmaker(engine)() as db:
            # make sure the commit sha we want to check out is in the repo
            db.execute(
                update(VulnerabilityDiscovery)
                .where(VulnerabilityDiscovery.id == fake_accepted_vds["id"])
                .values(pou_commit_sha1=repo.head.commit.hexsha)
            )

            gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchall()[0][0]

            vds = db.execute(
                select(VulnerabilityDiscovery).where(
                    VulnerabilityDiscovery.id == fake_accepted_vds["id"]
                )
            ).fetchall()[0][0]

            assert (
                gp.patch_applied is None
            ), f"patch_applied was {gp.patch_applied} immediately after creation"
            assert (
                gp.sanitizer_did_not_fire is None
            ), f"sanitizer_did_not_fire was {gp.sanitizer_did_not_fire} immediately after creation"
            assert gp.functional_tests_passed is None, (
                f"functional_tests_passed was {gp.functional_tests_passed} immediately "
                "after creation"
            )

        runner = TaskRunner(fake_cp)

        with mock.patch(
            "competition_api.cp_workspace.run",
            side_effect=build_mock_run(
                fake_accepted_vds["pov_data"],
                test_project_yaml["harnesses"][fake_accepted_vds["pov_harness"]][
                    "name"
                ],
                gp_patch=fake_gp["data"],
                sanitizer=(
                    None
                    if sanitizer_does_not_fire
                    else runner.workspace.project_yaml["sanitizers"][
                        fake_accepted_vds["pou_sanitizer"]
                    ]
                ),
                patch_returncode=0 if patch_applies else 1,
                tests_returncode=0 if functional_tests_pass else 1,
                container_name=test_project_yaml["docker_image"],
            ),
        ):
            await runner.test_gp(gp, vds)

        with sessionmaker(engine)() as db:
            db_gp = db.execute(
                select(GeneratedPatch).where(GeneratedPatch.id == fake_gp["id"])
            ).fetchall()[0][0]

            assert db_gp.patch_applied == patch_applies, (
                f"patch_applied was {db_gp.patch_applied} but patch_applies was "
                f"{patch_applies}"
            )
            assert db_gp.sanitizer_did_not_fire == (
                sanitizer_does_not_fire if patch_applies else None
            ), (
                f"sanitizer_did_not_fire was marked {db_gp.sanitizer_did_not_fire} but "
                f"sanitizer_does_not_fire was {sanitizer_does_not_fire} and "
                f"patch_applies was {patch_applies}"
            )
            assert db_gp.functional_tests_passed == (
                functional_tests_pass
                if patch_applies and sanitizer_does_not_fire
                else None
            ), (
                f"functional_tests_passed was marked {db_gp.functional_tests_passed} "
                f"but functional_tests_pass was {functional_tests_pass} and "
                f"patch_applies was {patch_applies} and sanitizer_does_not_fire was "
                f"{sanitizer_does_not_fire}"
            )
