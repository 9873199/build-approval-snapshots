# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import os
import sys

from pathlib import Path
from typing import Any

import pyproject_hooks
import pytest

from build import (
    ApprovedProjectBuilder,
    BuildBackendException,
    BuildPlan,
    CancellationToken,
    DependencyApprovalRequired,
    HookNotAuthorizedError,
    PlanChangedError,
    ProjectBuilder,
)
from build.approval import (
    UNKNOWN_DEPENDENCIES,
    ApprovalCancelled,
    ApprovedIsolatedEnvironment,
    approve_dynamic_dependencies,
    authorize_plan,
    build_authorized,
    install_approved_dependencies,
)


PROBE_BACKEND = r'''
import json
import os
import pathlib

MARKER = pathlib.Path(os.environ["APPROVAL_TEST_MARKER"])


def record(event, hook=None, config_settings=None):
    with MARKER.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({
            "event": event,
            "hook": hook,
            "config": config_settings,
        }, sort_keys=True) + "\n")


record("import")


def get_requires_for_build_wheel(config_settings=None):
    record("hook", "get_requires_for_build_wheel", config_settings)
    return ["local-dynamic==1.0"]


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    record("hook", "prepare_metadata_for_build_wheel", config_settings)
    distinfo = pathlib.Path(metadata_directory) / "demo-1.0.dist-info"
    distinfo.mkdir(parents=True, exist_ok=True)
    (distinfo / "METADATA").write_text("Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n", encoding="utf-8")
    return distinfo.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    record("hook", "build_wheel", config_settings)
    if config_settings and config_settings.get("fail_build") == "yes":
        raise RuntimeError("intentional harmless build failure")
    wheel_directory = pathlib.Path(wheel_directory)
    wheel_directory.mkdir(parents=True, exist_ok=True)
    name = "demo-1.0-py3-none-any.whl"
    (wheel_directory / name).write_bytes(b"PK\x03\x04harmless")
    return name
'''


HOOKLESS_BACKEND = r'''
import json
import os
import pathlib

MARKER = pathlib.Path(os.environ["APPROVAL_TEST_MARKER"])
with MARKER.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"event": "import", "hook": None, "config": None}) + "\n")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    with MARKER.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": "hook", "hook": "build_wheel", "config": config_settings}) + "\n")
    wheel_directory = pathlib.Path(wheel_directory)
    wheel_directory.mkdir(parents=True, exist_ok=True)
    name = "demo-1.0-py3-none-any.whl"
    (wheel_directory / name).write_bytes(b"PK\x03\x04harmless")
    return name
'''


PWN_BACKEND = r'''
import os
import pathlib

pathlib.Path(os.environ["APPROVAL_TEST_PWN"]).write_text("pwned", encoding="utf-8")
'''


class FakeIsolatedEnvironment:
    def __init__(self) -> None:
        self.python_executable = sys.executable
        self.installed: list[list[str]] = []

    def make_extra_environ(self) -> dict[str, str]:
        return {}

    def install(self, requirements: list[str]) -> None:
        self.installed.append(list(requirements))


def write_project(
    root: Path,
    *,
    backend_text: str = PROBE_BACKEND,
    backend_directory: str = 'backend',
    backend_module: str = 'probe_backend.py',
    backend_path: str | None = 'backend',
) -> Path:
    backend_dir = root / backend_directory
    backend_dir.mkdir(parents=True, exist_ok=True)
    backend_dir.joinpath(backend_module).write_text(backend_text, encoding='utf-8')
    backend_path_line = '' if backend_path is None else f'backend-path = [{backend_path!r}]\n'
    root.joinpath('pyproject.toml').write_text(
        f'''
[build-system]
requires = []
build-backend = "probe_backend"
{backend_path_line}
[project]
name = "demo"
version = "1.0"
''',
        encoding='utf-8',
    )
    return root


def read_events(marker: Path) -> list[dict[str, Any]]:
    if not marker.exists():
        return []
    return [json.loads(line) for line in marker.read_text(encoding='utf-8').splitlines() if line]


def hook_events(events: list[dict[str, Any]], hook_name: str) -> list[dict[str, Any]]:
    return [event for event in events if event['event'] == 'hook' and event['hook'] == hook_name]


def make_directory_link(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=True)
    except OSError:
        if os.name != 'nt':
            raise
        import _winapi

        _winapi.CreateJunction(str(target.resolve()), str(link))


@pytest.fixture
def marked_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, Path]:
    project = tmp_path / 'project'
    project.mkdir()
    write_project(project)
    marker = tmp_path / 'calls.jsonl'
    pwn = tmp_path / 'pwned'
    monkeypatch.setenv('APPROVAL_TEST_MARKER', str(marker))
    monkeypatch.setenv('APPROVAL_TEST_PWN', str(pwn))
    return project, marker, pwn


def recording_runner(calls: list[tuple[list[str], str | None]]) -> Any:
    def runner(cmd: Any, cwd: str | None = None, extra_environ: Any = None) -> None:
        calls.append((list(cmd), cwd))
        pyproject_hooks.default_subprocess_runner(cmd, cwd, extra_environ)

    return runner


def test_static_plan_does_not_import_backend(marked_project: tuple[Path, Path, Path]) -> None:
    project, marker, _ = marked_project

    plan = BuildPlan.create(
        project,
        hooks=['build_wheel', 'get_requires_for_build_wheel'],
        config_settings={'mode': 'safe', 'repeated': ['a', 'b']},
    )

    assert plan.backend_name == 'probe_backend'
    assert plan.backend_path == ('backend',)
    assert plan.static_dependencies == ()
    assert plan.hook_names == ('build_wheel', 'get_requires_for_build_wheel')
    assert plan.dynamic_dependencies is None
    assert plan.dynamic_dependency_state == 'unknown'
    assert plan.dynamic_dependencies_unknown is True
    assert plan.unknown_dynamic_dependencies is UNKNOWN_DEPENDENCIES
    assert plan.config_settings['mode'] == 'safe'
    assert plan.config_settings['repeated'] == ('a', 'b')
    assert 'pyproject.toml' in plan.file_digests
    assert 'backend/probe_backend.py' in plan.file_digests
    with pytest.raises(DependencyApprovalRequired):
        list(plan.unknown_dynamic_dependencies)
    assert read_events(marker) == []


def test_plan_digest_binds_content_and_not_only_directory_name(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, _, _ = marked_project
    first = BuildPlan.create(project, hooks=['build_wheel'])

    copy = tmp_path / 'same-content'
    copy.mkdir()
    write_project(copy)
    second = BuildPlan.create(copy, hooks=['build_wheel'])
    assert first.plan_digest == second.plan_digest
    assert first.snapshot_digest == second.snapshot_digest

    (project / 'backend' / 'probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')
    changed = BuildPlan.create(project, hooks=['build_wheel'])
    assert changed.plan_digest != first.plan_digest
    assert changed.snapshot_digest != first.snapshot_digest


def test_authorized_build_runs_exact_hook_with_custom_runner_and_freeze(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    output = tmp_path / 'dist'
    runner_calls: list[tuple[list[str], str | None]] = []
    plan = BuildPlan.create(project, hooks=['build_wheel'], config_settings={'mode': 'safe'})
    authorization = authorize_plan(plan, hooks=['build_wheel'])

    with ApprovedProjectBuilder(plan, authorization, runner=recording_runner(runner_calls)) as builder:
        result = Path(builder.build_wheel(output))

        assert result.exists()
        assert builder.invoked_hooks == ['build_wheel']
        assert len(runner_calls) == 1
        assert Path(runner_calls[0][1] or '').resolve() == Path(builder.frozen_source_path).resolve()
        assert Path(builder.frozen_source_path) != project

    events = read_events(marker)
    assert len([event for event in events if event['event'] == 'import']) == 1
    assert len(hook_events(events, 'build_wheel')) == 1
    assert hook_events(events, 'build_wheel')[0]['config'] == {'mode': 'safe'}


def test_file_swap_after_plan_is_rejected_before_authorization(
    marked_project: tuple[Path, Path, Path]
) -> None:
    project, marker, pwn = marked_project
    plan = BuildPlan.create(project, hooks=['build_wheel'])
    (project / 'backend' / 'probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')

    with pytest.raises(PlanChangedError):
        authorize_plan(plan, hooks=['build_wheel'])

    assert read_events(marker) == []
    assert not pwn.exists()


def test_file_swap_after_authorization_is_rejected_at_execution(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, pwn = marked_project
    output = tmp_path / 'dist'
    plan = BuildPlan.create(project, hooks=['build_wheel'])

    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            (project / 'backend' / 'probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')

            with pytest.raises(PlanChangedError):
                builder.build_wheel(output)

    assert read_events(marker) == []
    assert not pwn.exists()


def test_directory_replacement_changes_backend_path_identity(
    marked_project: tuple[Path, Path, Path]
) -> None:
    project, _, pwn = marked_project
    plan = BuildPlan.create(project, hooks=['build_wheel'])

    (project / 'backend').rename(project / 'backend_original')
    replacement = project / 'backend'
    replacement.mkdir()
    replacement.joinpath('probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')

    with pytest.raises(PlanChangedError):
        authorize_plan(plan, hooks=['build_wheel'])
    assert not pwn.exists()


def test_symlink_retarget_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / 'symlink-project'
    v1 = project / 'backend-v1'
    v2 = project / 'backend-v2'
    v1.mkdir(parents=True)
    v2.mkdir(parents=True)
    (v1 / 'probe_backend.py').write_text(PROBE_BACKEND, encoding='utf-8')
    (v2 / 'probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')
    write_project(project, backend_path='backend-link', backend_directory='backend-v1')
    link = project / 'backend-link'
    try:
        make_directory_link(link, v1)
    except OSError as exception:
        pytest.skip(f'Directory symlinks/junctions are unavailable: {exception}')

    marker = tmp_path / 'calls.jsonl'
    pwn = tmp_path / 'pwned'
    monkeypatch.setenv('APPROVAL_TEST_MARKER', str(marker))
    monkeypatch.setenv('APPROVAL_TEST_PWN', str(pwn))

    plan = BuildPlan.create(project, hooks=['build_wheel'])
    assert any(entry.path == 'backend-link' for entry in plan.source_files)

    os.rmdir(link)
    make_directory_link(link, v2)

    with pytest.raises(PlanChangedError):
        authorize_plan(plan, hooks=['build_wheel'])
    assert not pwn.exists()
    assert read_events(marker) == []


def test_symlink_retarget_after_authorization_is_rejected_at_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / 'symlink-project-live'
    v1 = project / 'backend-v1'
    v2 = project / 'backend-v2'
    v1.mkdir(parents=True)
    v2.mkdir(parents=True)
    (v1 / 'probe_backend.py').write_text(PROBE_BACKEND, encoding='utf-8')
    (v2 / 'probe_backend.py').write_text(PWN_BACKEND, encoding='utf-8')
    write_project(project, backend_path='backend-link', backend_directory='backend-v1')
    link = project / 'backend-link'
    try:
        make_directory_link(link, v1)
    except OSError as exception:
        pytest.skip(f'Directory symlinks/junctions are unavailable: {exception}')

    marker = tmp_path / 'calls.jsonl'
    pwn = tmp_path / 'pwned'
    monkeypatch.setenv('APPROVAL_TEST_MARKER', str(marker))
    monkeypatch.setenv('APPROVAL_TEST_PWN', str(pwn))
    output = tmp_path / 'dist'

    plan = BuildPlan.create(project, hooks=['build_wheel'])
    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            os.rmdir(link)
            make_directory_link(link, v2)
            with pytest.raises(PlanChangedError):
                builder.build_wheel(output)

    assert not pwn.exists()
    assert read_events(marker) == []


def test_race_after_verification_still_executes_frozen_approved_bytes(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, pwn = marked_project
    output = tmp_path / 'dist'
    target = project / 'backend' / 'probe_backend.py'
    plan = BuildPlan.create(project, hooks=['build_wheel'], config_settings={'mode': 'safe'})

    def swapping_runner(cmd: Any, cwd: str | None, extra_environ: Any) -> None:
        # Simulate an attacker winning the race after approval verification but before spawn.
        target.write_text(PWN_BACKEND, encoding='utf-8')
        pyproject_hooks.default_subprocess_runner(cmd, cwd, extra_environ)

    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization, runner=swapping_runner) as builder:
            result = Path(builder.build_wheel(output))
            assert result.exists()

    events = read_events(marker)
    assert len(hook_events(events, 'build_wheel')) == 1
    assert not pwn.exists()


def test_config_input_mutation_is_not_bound_or_used(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    output = tmp_path / 'dist'
    config = {'mode': 'safe', 'items': ['a']}
    plan = BuildPlan.create(project, hooks=['build_wheel'], config_settings=config)

    config['mode'] = 'evil'
    config['items'].append('b')
    assert plan.config_settings['mode'] == 'safe'
    assert plan.config_settings['items'] == ('a',)

    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            result = builder.build_wheel(output)
            assert Path(result).exists()
            with pytest.raises(PlanChangedError):
                builder.build_wheel(tmp_path / 'dist2', config_settings={'mode': 'evil', 'items': ('a',)})

    events = read_events(marker)
    assert hook_events(events, 'build_wheel')[0]['config'] == {'mode': 'safe', 'items': ['a']}


def test_approval_callback_cannot_mutate_canonical_plan(
    marked_project: tuple[Path, Path, Path]
) -> None:
    project, marker, _ = marked_project
    plan = BuildPlan.create(project, hooks=['build_wheel'])

    def mutate(plan_to_mutate: BuildPlan) -> bool:
        plan_to_mutate.config_settings['injected'] = 'yes'  # type: ignore[index]
        return True

    with pytest.raises(Exception):
        authorize_plan(plan, approver=mutate)
    assert read_events(marker) == []


def test_cancelled_token_prevents_execution(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    output = tmp_path / 'dist'
    token = CancellationToken()
    plan = BuildPlan.create(project, hooks=['build_wheel'])

    with authorize_plan(plan, hooks=['build_wheel'], cancellation=token) as authorization:
        with ApprovedProjectBuilder(plan, authorization, cancellation=token) as builder:
            token.cancel()
            with pytest.raises(ApprovalCancelled):
                builder.build_wheel(output)

    assert read_events(marker) == []


def test_unapproved_build_hook_cannot_run(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    plan = BuildPlan.create(project, hooks=['prepare_metadata_for_build_wheel'])
    output = tmp_path / 'dist'

    with authorize_plan(plan, hooks=['prepare_metadata_for_build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            with pytest.raises(HookNotAuthorizedError):
                builder.build_wheel(output)

    assert read_events(marker) == []


def test_direct_private_hook_caller_cannot_bypass_authorization(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    plan = BuildPlan.create(project, hooks=['build_wheel'])

    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            with pytest.raises(HookNotAuthorizedError):
                builder._hook.build_sdist(str(tmp_path / 'dist'), {})

    assert read_events(marker) == []


def test_metadata_approval_does_not_escalate_to_build_wheel(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    metadata_dir = tmp_path / 'metadata'
    plan = BuildPlan.create(project, hooks=['prepare_metadata_for_build_wheel'])

    with authorize_plan(plan, hooks=['prepare_metadata_for_build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            metadata_path = Path(builder.metadata_path(metadata_dir))
            assert metadata_path.exists()

    events = read_events(marker)
    assert len(hook_events(events, 'prepare_metadata_for_build_wheel')) == 1
    assert hook_events(events, 'build_wheel') == []


def test_missing_metadata_hook_does_not_fallback_without_build_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / 'hookless'
    project.mkdir()
    write_project(project, backend_text=HOOKLESS_BACKEND)
    marker = tmp_path / 'calls.jsonl'
    monkeypatch.setenv('APPROVAL_TEST_MARKER', str(marker))
    metadata_dir = tmp_path / 'metadata'

    plan = BuildPlan.create(project, hooks=['prepare_metadata_for_build_wheel'])
    with authorize_plan(plan, hooks=['prepare_metadata_for_build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            with pytest.raises(HookNotAuthorizedError):
                builder.metadata_path(metadata_dir)

    events = read_events(marker)
    assert hook_events(events, 'build_wheel') == []


def test_build_failure_runs_hook_once_without_retry_or_escalation(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    output = tmp_path / 'dist'
    plan = BuildPlan.create(project, hooks=['build_wheel'], config_settings={'fail_build': 'yes'})

    with authorize_plan(plan, hooks=['build_wheel']) as authorization:
        with ApprovedProjectBuilder(plan, authorization) as builder:
            with pytest.raises(BuildBackendException):
                builder.build_wheel(output)
            assert builder.invoked_hooks == ['build_wheel']

    events = read_events(marker)
    assert len(hook_events(events, 'build_wheel')) == 1


def test_dynamic_dependencies_require_explicit_dependency_grant(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, _, _ = marked_project
    output = tmp_path / 'dist'
    environment = FakeIsolatedEnvironment()
    plan = BuildPlan.create(project, hooks=['get_requires_for_build_wheel', 'build_wheel'])
    authorization = authorize_plan(plan, hooks=['get_requires_for_build_wheel', 'build_wheel'])

    with ApprovedProjectBuilder.from_isolated_env(environment, plan, authorization) as builder:
        requirements = builder.get_requires_for_build_wheel()
        assert requirements == {'local-dynamic==1.0'}

        with pytest.raises(DependencyApprovalRequired):
            approve_dynamic_dependencies(authorization, requirements)

        grant = approve_dynamic_dependencies(authorization, requirements, approver=lambda requested: True)
        install_approved_dependencies(environment, grant)
        result = builder.build_wheel(output)
        assert Path(result).exists()

    assert environment.installed == [['local-dynamic==1.0']]


def test_high_level_build_stops_when_dynamic_dependencies_denied(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    environment = FakeIsolatedEnvironment()
    plan = BuildPlan.create(project, hooks=['get_requires_for_build_wheel', 'build_wheel'])
    authorization = authorize_plan(plan, hooks=['get_requires_for_build_wheel', 'build_wheel'])

    with pytest.raises(DependencyApprovalRequired):
        build_authorized(
            plan,
            authorization,
            output_directory=tmp_path / 'dist',
            isolated_environment=environment,
            dependency_approver=lambda requested: False,
        )

    events = read_events(marker)
    assert len(hook_events(events, 'get_requires_for_build_wheel')) == 1
    assert hook_events(events, 'build_wheel') == []


def test_authorization_builder_dependency_helper(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, _, _ = marked_project
    environment = FakeIsolatedEnvironment()
    plan = BuildPlan.create(project, hooks=['get_requires_for_build_wheel', 'build_wheel'])

    with plan.authorize(hooks=['get_requires_for_build_wheel', 'build_wheel']) as authorization:
        with authorization.builder(
            python_executable=environment.python_executable,
        ) as builder:
            grant = builder.resolve_and_approve_dependencies(
                environment,
                approver=lambda requested: requested == ('local-dynamic==1.0',),
            )
            assert grant.requirements == ('local-dynamic==1.0',)
            assert Path(builder.build_wheel(tmp_path / 'dist')).exists()

    assert environment.installed == [['local-dynamic==1.0']]


def test_guarded_environment_blocks_generic_install(marked_project: tuple[Path, Path, Path]) -> None:
    project, _, _ = marked_project
    environment = FakeIsolatedEnvironment()
    plan = BuildPlan.create(project, hooks=['build_wheel'])
    authorization = authorize_plan(plan, hooks=['build_wheel'])
    guarded = ApprovedIsolatedEnvironment(environment, authorization)

    with pytest.raises(DependencyApprovalRequired):
        guarded.install(['anything'])
    guarded.install_static()
    assert environment.installed == [[]]


def test_legacy_project_builder_still_runs_without_approval(
    marked_project: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    project, marker, _ = marked_project
    result = ProjectBuilder(str(project)).build('wheel', str(tmp_path / 'dist'))
    assert Path(result).exists()
    assert len(hook_events(read_events(marker), 'build_wheel')) == 1


def test_authorization_digest_detects_dataclass_tampering(
    marked_project: tuple[Path, Path, Path]
) -> None:
    project, _, _ = marked_project
    plan = BuildPlan.create(project, hooks=['build_wheel'])
    authorization = authorize_plan(plan, hooks=['build_wheel'])
    forged = __import__('dataclasses').replace(authorization, hooks=('build_sdist',))

    with pytest.raises(Exception):
        ApprovedProjectBuilder(plan, forged)
