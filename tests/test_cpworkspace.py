# pylint: disable=unused-argument

from competition_api.cp_workspace import CPWorkspace


class TestCPWorkspace:
    @staticmethod
    def test_init(test_project_yaml, repo):
        workspace = CPWorkspace(test_project_yaml["cp_name"])
        assert workspace.workdir
        assert workspace.project_yaml == test_project_yaml
        assert workspace.repo
