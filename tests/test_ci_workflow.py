"""
Tests that verify .github/workflows/ci.yml itself is structurally
correct — valid YAML, correct triggers, correct steps, correct tools.

This does NOT run the workflow (that only happens on GitHub's
servers). It confirms the FILE is well-formed and contains what
issue #31 asked for, so you can demo/verify it locally in VS Code.

Run with:
    pytest tests/test_ci_workflow.py -v
"""

import os

import pytest
import yaml

CI_YML_PATH = os.path.join(".github", "workflows", "ci.yml")
FLAKE8_CONFIG_PATH = ".flake8"


@pytest.fixture(scope="module")
def workflow():
    """Loads and parses ci.yml once for all tests in this file."""
    assert os.path.exists(CI_YML_PATH), (
        f"{CI_YML_PATH} not found — are you running pytest from the " "repo root?"
    )
    with open(CI_YML_PATH, "r") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# File existence / validity
# ---------------------------------------------------------------------------


def test_ci_yml_exists():
    assert os.path.exists(CI_YML_PATH)


def test_ci_yml_is_valid_yaml(workflow):
    # If yaml.safe_load succeeded in the fixture, this already passed —
    # this test just makes the check explicit and named on its own.
    assert workflow is not None
    assert isinstance(workflow, dict)


def test_flake8_config_exists():
    assert os.path.exists(FLAKE8_CONFIG_PATH)


# ---------------------------------------------------------------------------
# Triggers
# ---------------------------------------------------------------------------


def test_triggers_on_push_to_main(workflow):
    # PyYAML parses the unquoted key "on" as boolean True in YAML 1.1
    triggers = workflow.get("on") or workflow.get(True)
    assert triggers is not None, "No 'on:' trigger section found"
    assert "push" in triggers
    assert "main" in triggers["push"]["branches"]


def test_triggers_on_pull_request_to_main(workflow):
    triggers = workflow.get("on") or workflow.get(True)
    assert "pull_request" in triggers
    assert "main" in triggers["pull_request"]["branches"]


# ---------------------------------------------------------------------------
# Matrix / job structure
# ---------------------------------------------------------------------------


def test_has_build_and_test_job(workflow):
    assert "build-and-test" in workflow["jobs"]


def test_runs_on_ubuntu(workflow):
    job = workflow["jobs"]["build-and-test"]
    assert job["runs-on"] == "ubuntu-latest"


def test_python_version_matrix_covers_required_versions(workflow):
    job = workflow["jobs"]["build-and-test"]
    versions = job["strategy"]["matrix"]["python-version"]
    for required in ["3.9", "3.10", "3.11", "3.12"]:
        assert required in versions, f"Missing Python {required} in matrix"


# ---------------------------------------------------------------------------
# Required steps present
# ---------------------------------------------------------------------------


def _step_names(workflow):
    steps = workflow["jobs"]["build-and-test"]["steps"]
    return [step.get("name", "") for step in steps]


def test_has_checkout_step(workflow):
    assert any("Checkout" in name for name in _step_names(workflow))


def test_has_python_setup_step(workflow):
    assert any("Set up Python" in name for name in _step_names(workflow))


def test_has_dependency_install_step(workflow):
    assert any("Install Dependencies" in name for name in _step_names(workflow))


def test_has_black_step(workflow):
    assert any("Black" in name for name in _step_names(workflow))


def test_has_flake8_step(workflow):
    assert any("Flake8" in name for name in _step_names(workflow))


def test_has_pytest_step(workflow):
    assert any("Pytest" in name for name in _step_names(workflow))


# ---------------------------------------------------------------------------
# Step content — the actual commands being run
# ---------------------------------------------------------------------------


def _get_step_run(workflow, name_contains):
    steps = workflow["jobs"]["build-and-test"]["steps"]
    for step in steps:
        if name_contains in step.get("name", ""):
            return step.get("run", "")
    return None


def test_black_step_uses_check_flag(workflow):
    run_cmd = _get_step_run(workflow, "Black")
    assert run_cmd is not None
    assert "--check" in run_cmd


def test_flake8_step_checks_for_syntax_errors(workflow):
    run_cmd = _get_step_run(workflow, "Flake8")
    assert run_cmd is not None
    assert "E9" in run_cmd  # syntax error code
    assert "F82" in run_cmd  # undefined name code


def test_pytest_step_includes_coverage(workflow):
    run_cmd = _get_step_run(workflow, "Pytest")
    assert run_cmd is not None
    assert "--cov" in run_cmd


def test_pytest_step_sets_pythonpath(workflow):
    steps = workflow["jobs"]["build-and-test"]["steps"]
    pytest_step = next(s for s in steps if "Pytest" in s.get("name", ""))
    assert pytest_step.get("env", {}).get("PYTHONPATH") == "."