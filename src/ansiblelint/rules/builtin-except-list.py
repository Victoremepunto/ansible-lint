import sys
from typing import Any, Dict, Optional, Union

from ansiblelint.rules.only_builtins import OnlyBuiltinsRule
from ansiblelint.file_utils import Lintable


class OnlyBuiltinsExceptListRule(OnlyBuiltinsRule):

    exceptions_list = {"firewalld", "ini_file", "mount", "selinux", "modprobe", "sysctl"}

    """Use only builtin actions and the ones listed"""
    id = "only-builtins-except-list"
    description = "Used modules must be either builtin or included in the provided list"
    severity = "HIGH"
    tags = ["opt-in", "experimental"]

    def matchtask(
        self, task: Dict[str, Any], file: Optional[Lintable] = None
    ) -> Union[bool, str]:

        only_builtins_result = super().matchtask(task, file)

        if only_builtins_result:
            from pdb import set_trace; set_trace()
            return task["action"]["__ansible_module_original__"] not in self.exceptions_list
        else:
            return only_builtins_result


# testing code to be loaded only with pytest or when executed the rule file
if "pytest" in sys.modules:

    # pylint: disable=ungrouped-imports
    import pytest

    from ansiblelint.constants import VIOLATIONS_FOUND_RC
    from ansiblelint.testing import RunFromText, run_ansible_lint

    SUCCESS_PLAY = """
- hosts: localhost
  tasks:
  - name: foo (fqcn)
    firewalld: This rule should not get matched by the only-builtins-except-list rule
    """

    def test_only_builtin_except_list_fail() -> None:
        """Test rule matches."""
        result = run_ansible_lint(
            "--config-file=/dev/null",
            "--warn-list=",
            "--enable-list",
            "only-builtins-except-list",
            "examples/playbooks/rule-only-builtins.yml",
        )
        assert result.returncode == VIOLATIONS_FOUND_RC
        assert "Finished with 1 failure(s)" in result.stderr
        assert "only-builtins-except-list" in result.stdout

    @pytest.mark.parametrize(
        "rule_runner", (OnlyBuiltinsExceptListRule,), indirect=["rule_runner"]
    )
    def test_only_builtin_except_list_pass(rule_runner: RunFromText) -> None:
        """Test rule does not match."""
        results = rule_runner.run_playbook(SUCCESS_PLAY)
        assert len(results) == 0, results
