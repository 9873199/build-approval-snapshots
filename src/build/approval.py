# SPDX-License-Identifier: MIT

"""Plan, explicitly authorize, freeze, and execute PEP 517 hooks.

This module is an integrity boundary, not an operating-system sandbox.  It
never imports a backend while planning.  Execution runs against a private,
materialized copy of the approved source snapshot; a last live revalidation
produces a clear stale-authorization error, while the private copy closes the
check-to-subprocess read race.  Arbitrary backend code can still access
absolute paths, the network, or processes as the current user.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import types
import weakref

from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import pyproject_hooks

from ._builder import ProjectBuilder, _parse_build_system_table, _read_pyproject_toml, _validate_source_directory
from ._exceptions import (
    ApprovalCancelled,
    ApprovalError,
    AuthorizationError,
    DependencyApprovalRequired,
    HookNotAuthorizedError,
    PlanChangedError,
    PlanValidationError,
)
from ._types import ConfigSettings, StrPath, SubprocessRunner


SCHEMA_VERSION = 'build-approval/v1'
SHA256 = 'sha256'


class _UnknownDependencies:
    """Sentinel proving that dynamic dependencies were not resolved."""

    _instance: _UnknownDependencies | None = None

    def __new__(cls) -> _UnknownDependencies:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    state = 'unknown'
    is_unknown = True

    def __repr__(self) -> str:
        return '<UNKNOWN_DEPENDENCIES: authorize get_requires_for_build_* to resolve>'

    def __bool__(self) -> bool:
        return True

    def __iter__(self) -> Any:
        msg = 'Dynamic dependencies are unknown until an authorized get_requires_for_build_* hook runs'
        raise DependencyApprovalRequired(msg)


UNKNOWN_DEPENDENCIES = _UnknownDependencies()
UNKNOWN = UNKNOWN_DEPENDENCIES
DYNAMIC_DEPENDENCIES_UNKNOWN = UNKNOWN_DEPENDENCIES


HOOK_DEPENDENCIES_WHEEL = 'get_requires_for_build_wheel'
HOOK_METADATA_WHEEL = 'prepare_metadata_for_build_wheel'
HOOK_BUILD_WHEEL = 'build_wheel'
HOOK_DEPENDENCIES_SDIST = 'get_requires_for_build_sdist'
HOOK_BUILD_SDIST = 'build_sdist'
HOOK_DEPENDENCIES_EDITABLE = 'get_requires_for_build_editable'
HOOK_METADATA_EDITABLE = 'prepare_metadata_for_build_editable'
HOOK_BUILD_EDITABLE = 'build_editable'

KNOWN_HOOKS = frozenset({
    HOOK_DEPENDENCIES_WHEEL,
    HOOK_METADATA_WHEEL,
    HOOK_BUILD_WHEEL,
    HOOK_DEPENDENCIES_SDIST,
    HOOK_BUILD_SDIST,
    HOOK_DEPENDENCIES_EDITABLE,
    HOOK_METADATA_EDITABLE,
    HOOK_BUILD_EDITABLE,
})

_HOOK_ALIASES = {
    'dependencies': None,  # resolved using distribution
    'get_requires_for_build': None,
    'metadata': None,
    'prepare_metadata': None,
    'prepare_metadata_for_build': None,
    'build': None,
}


class CancellationToken:
    """Cooperative cancellation checked before filesystem freeze and hooks."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self.cancelled:
            raise ApprovalCancelled('Build approval was cancelled before the authorized hook started')


CancellationLike = CancellationToken | threading.Event | Callable[[], bool] | None


def _cancellation_token(value: CancellationLike) -> CancellationToken:
    if value is None:
        return CancellationToken()
    if isinstance(value, CancellationToken):
        return value
    token = CancellationToken()
    if isinstance(value, threading.Event):
        original = value

        def sync_event() -> bool:
            if original.is_set():
                token.cancel()
            return token.cancelled

        # The returned wrapper is used immediately and keeps the caller event authoritative.
        token._poll = sync_event  # type: ignore[attr-defined]
        return token
    if callable(value):
        original_call = value

        def sync_call() -> bool:
            try:
                cancelled = bool(original_call())
            except Exception:
                cancelled = True
                token.cancel()
                raise
            if cancelled:
                token.cancel()
            return cancelled

        token._poll = sync_call  # type: ignore[attr-defined]
    return token


def _check_cancelled(token: CancellationToken) -> None:
    poll = getattr(token, '_poll', None)
    if callable(poll):
        poll()
    token.raise_if_cancelled()


def _canonical_json(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _sha256_bytes(payload: object) -> str:
    return hashlib.sha256(_canonical_json(payload)).hexdigest()


def _config_to_json(config: Mapping[str, str | tuple[str, ...]]) -> dict[str, str | list[str]]:
    return {key: value if isinstance(value, str) else list(value) for key, value in sorted(config.items())}


def _config_for_hook(config: Mapping[str, str | tuple[str, ...]]) -> dict[str, str | list[str]]:
    return {key: value if isinstance(value, str) else list(value) for key, value in config.items()}


def normalize_config_settings(config_settings: ConfigSettings | None) -> Mapping[str, str | tuple[str, ...]]:
    """Return an immutable, canonical copy of PEP 517 config settings."""
    if config_settings is None:
        return types.MappingProxyType({})
    if not isinstance(config_settings, Mapping):
        msg = 'config_settings must be a mapping'
        raise PlanValidationError(msg)

    normalized: dict[str, str | tuple[str, ...]] = {}
    for key, value in config_settings.items():
        if not isinstance(key, str):
            msg = 'config_settings keys must be strings'
            raise PlanValidationError(msg)
        if isinstance(value, str):
            normalized[key] = value
        elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
            values = tuple(value)
            if not all(isinstance(item, str) for item in values):
                msg = f'config_settings[{key!r}] values must all be strings'
                raise PlanValidationError(msg)
            normalized[key] = values
        else:
            msg = f'config_settings[{key!r}] must be a string or sequence of strings'
            raise PlanValidationError(msg)
    return types.MappingProxyType(normalized)


@dataclass(frozen=True)
class SourceEntry:
    """One normalized filesystem record in the approved source snapshot."""

    path: str
    kind: str
    sha256: str | None = None
    size: int = 0
    link_target: str | None = None
    resolved_target: str | None = None


@dataclass(frozen=True)
class SourceSnapshot:
    """Content and symlink identity for a complete source tree."""

    source_dir: str
    resolved_source_dir: str
    entries: tuple[SourceEntry, ...]
    digest: str
    content_digest: str

    @property
    def files(self) -> Mapping[str, str]:
        return types.MappingProxyType({
            entry.path: entry.sha256
            for entry in self.entries
            if entry.sha256 is not None
        })

    def changed_entries_from(self, other: SourceSnapshot) -> list[str]:
        old = {entry.path: entry for entry in self.entries}
        new = {entry.path: entry for entry in other.entries}
        changed = [path for path in sorted(old.keys() | new.keys()) if old.get(path) != new.get(path)]
        return changed


def _path_identity(path: str) -> str:
    return os.path.normcase(os.path.abspath(os.path.realpath(path)))


def _canonical_link_target(resolved_target: str, source_root: str) -> str:
    """Prefer a root-relative target so identical relocated trees hash alike."""

    prefix = '\\\\?\\'
    resolved_target = os.path.normpath(resolved_target.removeprefix(prefix))
    source_root = os.path.normpath(os.path.realpath(source_root).removeprefix(prefix))
    try:
        relative = os.path.relpath(resolved_target, source_root)
    except ValueError:
        return os.path.normcase(resolved_target)
    if relative == '..' or relative.startswith(f'..{os.sep}'):
        return os.path.normcase(resolved_target)
    return relative.replace(os.sep, '/')


def _hash_and_copy_file(source: str, destination: str | None) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(source, 'rb') as source_file:  # noqa: PTH123 - streaming untrusted bytes, never exec
        output = open(destination, 'wb') if destination is not None else contextlib.nullcontext()  # noqa: PTH123
        with output as destination_file:
            while chunk := source_file.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
                if destination_file is not None:
                    destination_file.write(chunk)
    return digest.hexdigest(), size


def _scan_or_materialize(
    source_root: StrPath,
    destination_root: StrPath | None = None,
    cancellation: CancellationToken | None = None,
) -> SourceSnapshot:
    source_root = os.path.abspath(os.fspath(source_root))
    destination_root = None if destination_root is None else os.path.abspath(os.fspath(destination_root))
    if destination_root is not None:
        os.makedirs(destination_root, exist_ok=True)

    entries: list[SourceEntry] = []

    def walk(source_path: str, relative_path: str, destination_path: str | None, ancestors: set[str]) -> None:
        if cancellation is not None:
            _check_cancelled(cancellation)

        try:
            stat_result = os.lstat(source_path)
        except OSError as exception:
            msg = f'Cannot inspect source path {relative_path or "."!r}: {exception}'
            raise PlanValidationError(msg) from exception

        mode = stat_result.st_mode
        resolved_target = os.path.realpath(source_path)
        identity = _path_identity(source_path)

        if stat.S_ISLNK(mode):
            try:
                link_target = os.readlink(source_path)
            except OSError as exception:
                msg = f'Cannot read symlink {relative_path!r}: {exception}'
                raise PlanValidationError(msg) from exception

            try:
                target_stat = os.stat(source_path)
            except OSError as exception:
                msg = f'Refusing to freeze unresolved symlink {relative_path!r}: {exception}'
                raise PlanValidationError(msg) from exception

            if stat.S_ISDIR(target_stat.st_mode):
                if identity in ancestors:
                    msg = f'Symlink cycle detected at {relative_path!r} -> {link_target!r}'
                    raise PlanValidationError(msg)
                entries.append(
                    SourceEntry(
                        relative_path or '.',
                        'symlink-directory',
                        link_target=link_target,
                        resolved_target=_canonical_link_target(resolved_target, source_root),
                    )
                )
                if destination_path is not None and relative_path:
                    os.mkdir(destination_path)
                _walk_children(source_path, relative_path, destination_path, ancestors | {identity})
                return

            if not stat.S_ISREG(target_stat.st_mode):
                msg = f'Unsupported symlink target type at {relative_path!r}'
                raise PlanValidationError(msg)
            sha256, size = _hash_and_copy_file(
                source_path,
                None if destination_path is None or not relative_path else destination_path,
            )
            entries.append(
                SourceEntry(
                    relative_path,
                    'symlink-file',
                    sha256=sha256,
                    size=size,
                    link_target=link_target,
                    resolved_target=_canonical_link_target(resolved_target, source_root),
                )
            )
            return

        if stat.S_ISDIR(mode):
            if identity in ancestors:
                msg = f'Directory cycle detected at {relative_path!r}'
                raise PlanValidationError(msg)
            entries.append(SourceEntry(relative_path or '.', 'directory'))
            if destination_path is not None and relative_path:
                os.mkdir(destination_path)
            _walk_children(source_path, relative_path, destination_path, ancestors | {identity})
            return

        if stat.S_ISREG(mode):
            sha256, size = _hash_and_copy_file(source_path, destination_path)
            entries.append(SourceEntry(relative_path, 'file', sha256=sha256, size=size))
            return

        msg = f'Unsupported special file in source snapshot: {relative_path!r}'
        raise PlanValidationError(msg)

    def _walk_children(
        source_path: str,
        relative_path: str,
        destination_path: str | None,
        ancestors: set[str],
    ) -> None:
        try:
            with os.scandir(source_path) as iterator:
                children = sorted(iterator, key=lambda child: child.name)
        except OSError as exception:
            msg = f'Cannot list source directory {relative_path or "."!r}: {exception}'
            raise PlanValidationError(msg) from exception

        for child in children:
            child_relative = f'{relative_path}/{child.name}' if relative_path else child.name
            child_destination = None if destination_path is None else os.path.join(destination_path, child.name)
            walk(os.path.join(source_path, child.name), child_relative, child_destination, ancestors)

    walk(source_root, '', destination_root, set())
    entries.sort(key=lambda entry: entry.path)
    payload = [dataclasses.asdict(entry) for entry in entries]
    digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
    content_payload = {entry.path: entry.sha256 for entry in entries if entry.sha256 is not None}
    content_digest = hashlib.sha256(_canonical_json(content_payload)).hexdigest()
    return SourceSnapshot(
        source_dir=source_root,
        resolved_source_dir=os.path.realpath(source_root),
        entries=tuple(entries),
        digest=digest,
        content_digest=content_digest,
    )


def snapshot_source(source_dir: StrPath, *, cancellation: CancellationLike = None) -> SourceSnapshot:
    """Read-only, import-free snapshot of source contents and symlink targets."""

    token = _cancellation_token(cancellation)
    return _scan_or_materialize(source_dir, cancellation=token)


@dataclass(frozen=True)
class PlannedHook:
    name: str
    distribution: str | None
    dynamic_dependencies: None = None
    dynamic_dependency_state: str = 'unknown'


@dataclass(frozen=True)
class BuildPlan:
    """Canonical static build plan and bound source snapshot."""

    source_dir: str
    resolved_source_dir: str
    backend_name: str
    backend_path: tuple[str, ...]
    requires: tuple[str, ...]
    hooks: tuple[str, ...]
    config_settings: Mapping[str, str | tuple[str, ...]]
    snapshot: SourceSnapshot
    plan_digest: str
    schema_version: str = SCHEMA_VERSION
    dynamic_dependencies: None = None
    dynamic_dependency_state: str = 'unknown'
    project_dependencies: tuple[str, ...] | _UnknownDependencies = UNKNOWN_DEPENDENCIES
    hook_details: tuple[PlannedHook, ...] = ()
    backend_path_raw: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        source_dir: StrPath,
        hooks: str | Sequence[str] | None = None,
        *,
        distribution: str | None = None,
        config_settings: ConfigSettings | None = None,
        config: ConfigSettings | None = None,
        cancellation: CancellationLike = None,
        **kwargs: CancellationLike,
    ) -> BuildPlan:
        return plan_project(
            source_dir,
            hooks=hooks,
            distribution=distribution,
            config_settings=config_settings if config_settings is not None else config,
            cancellation=cancellation,
            **kwargs,
        )

    @property
    def backend(self) -> str:
        return self.backend_name

    @property
    def digest(self) -> str:
        return self.plan_digest

    @property
    def static_dependencies(self) -> tuple[str, ...]:
        return self.requires

    @property
    def build_system_requires(self) -> set[str]:
        return set(self.requires)

    @property
    def dynamic_dependencies_unknown(self) -> bool:
        return True

    @property
    def unknown_dynamic_dependencies(self) -> _UnknownDependencies:
        return UNKNOWN_DEPENDENCIES

    @property
    def dynamic_requirements(self) -> None:
        return None

    @property
    def hook_names(self) -> tuple[str, ...]:
        return self.hooks

    @property
    def planned_hooks(self) -> tuple[PlannedHook, ...]:
        return self.hook_details

    @property
    def config(self) -> Mapping[str, str | tuple[str, ...]]:
        return self.config_settings

    @property
    def source_digest(self) -> str:
        return self.snapshot.digest

    @property
    def snapshot_digest(self) -> str:
        return self.snapshot.digest

    @property
    def source_files(self) -> tuple[SourceEntry, ...]:
        return self.snapshot.entries

    @property
    def file_digests(self) -> Mapping[str, str]:
        return self.snapshot.files

    @property
    def source_digests(self) -> Mapping[str, str]:
        return self.snapshot.files

    @property
    def digests(self) -> Mapping[str, str]:
        return self.snapshot.files

    def authorize(
        self,
        hooks: str | Sequence[str] | Callable[[BuildPlan], bool | None] | bool | None = None,
        *,
        approver: Callable[[BuildPlan], bool | None] | None = None,
        approved: bool | None = None,
        cancellation: CancellationLike = None,
        should_cancel: CancellationLike = None,
        freeze: bool = True,
        **kwargs: CancellationLike,
    ) -> PlanAuthorization:
        return authorize_plan(
            self,
            hooks=hooks,
            approver=approver,
            approved=approved,
            cancellation=cancellation,
            should_cancel=should_cancel,
            freeze=freeze,
            **kwargs,
        )

    approve = authorize
    grant = authorize

    def to_dict(self) -> dict[str, Any]:
        return {
            'schema_version': self.schema_version,
            'source_dir': self.source_dir,
            'resolved_source_dir': self.resolved_source_dir,
            'backend_name': self.backend_name,
            'backend_path': list(self.backend_path),
            'backend_path_raw': list(self.backend_path_raw),
            'requires': list(self.requires),
            'dynamic_dependencies': 'unknown',
            'dynamic_dependency_state': self.dynamic_dependency_state,
            'hooks': list(self.hooks),
            'hook_details': [
                dataclasses.asdict(hook) | {'dynamic_dependencies': 'unknown'} for hook in self.hook_details
            ],
            'config_settings': _config_to_json(self.config_settings),
            'project_dependencies': (
                'unknown' if self.project_dependencies is UNKNOWN_DEPENDENCIES else list(self.project_dependencies)
            ),
            'plan_digest': self.plan_digest,
            'snapshot_digest': self.snapshot.digest,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, ensure_ascii=False, indent=2)


# Common semantic aliases.
ApprovalPlan = BuildPlan
BuildPlan.plan = BuildPlan.create  # type: ignore[attr-defined]
ApprovalPlan.plan = ApprovalPlan.create  # type: ignore[attr-defined]


def _canonical_hook_name(value: str, distribution: str | None) -> str:
    if value in KNOWN_HOOKS:
        return value
    dist = distribution or 'wheel'
    aliases = {
        'wheel': 'build_wheel',
        'sdist': 'build_sdist',
        'editable': 'build_editable',
        'dependencies': f'get_requires_for_build_{dist}',
        'get_requires_for_build': f'get_requires_for_build_{dist}',
        'get_requires': f'get_requires_for_build_{dist}',
        'metadata': f'prepare_metadata_for_build_{dist}',
        'prepare_metadata': f'prepare_metadata_for_build_{dist}',
        'prepare_metadata_for_build': f'prepare_metadata_for_build_{dist}',
        'build': f'build_{dist}',
    }
    if value in aliases:
        return aliases[value]
    msg = f'Unknown or non-standard PEP 517 hook {value!r}'
    raise HookNotAuthorizedError(msg)


def _plan_hooks(hooks: str | Sequence[str] | None, distribution: str | None) -> tuple[PlannedHook, ...]:
    if hooks is None:
        names = tuple(sorted(KNOWN_HOOKS))
    elif isinstance(hooks, str):
        names = (_canonical_hook_name(hooks, distribution),)
    else:
        names = tuple(dict.fromkeys(_canonical_hook_name(hook, distribution) for hook in hooks))
    return tuple(PlannedHook(name=name, distribution=distribution)
                 for name in names)


def _static_project_dependencies(pyproject: Mapping[str, Any]) -> tuple[str, ...] | _UnknownDependencies:
    project = pyproject.get('project')
    if not isinstance(project, Mapping):
        return UNKNOWN_DEPENDENCIES
    dynamic = project.get('dynamic', ())
    if isinstance(dynamic, Sequence) and not isinstance(dynamic, (str, bytes)) and 'dependencies' in dynamic:
        return UNKNOWN_DEPENDENCIES
    dependencies = project.get('dependencies')
    if dependencies is None:
        return ()
    if isinstance(dependencies, Sequence) and not isinstance(dependencies, (str, bytes)) and all(
        isinstance(item, str) for item in dependencies
    ):
        return tuple(dependencies)
    return UNKNOWN_DEPENDENCIES


def _normalize_backend_paths(source_dir: str, backend_path: Sequence[str]) -> tuple[str, ...]:
    source_key = os.path.normcase(os.path.abspath(source_dir))
    normalized_paths: list[str] = []
    for entry in backend_path:
        if os.path.isabs(entry):
            msg = 'backend-path entries must be relative to the source tree'
            raise PlanValidationError(msg)
        normalized = os.path.normpath(entry)
        absolute = os.path.abspath(os.path.join(source_dir, normalized))
        absolute_key = os.path.normcase(absolute)
        try:
            inside = os.path.commonpath([source_key, absolute_key]) == source_key
        except ValueError:
            inside = False
        if not inside:
            msg = f'backend-path entry {entry!r} resolves outside the source tree'
            raise PlanValidationError(msg)
        normalized_paths.append(normalized.replace(os.sep, '/'))
    return tuple(normalized_paths)


def plan_project(
    source_dir: StrPath,
    hooks: str | Sequence[str] | None = None,
    *,
    distribution: str | None = None,
    config_settings: ConfigSettings | None = None,
    config: ConfigSettings | None = None,
    cancellation: CancellationLike = None,
    should_cancel: CancellationLike = None,
    cancel: CancellationLike = None,
    cancel_token: CancellationLike = None,
) -> BuildPlan:
    """Create a static plan without constructing a backend caller or importing code."""

    cancellation = cancellation if cancellation is not None else should_cancel
    cancellation = cancellation if cancellation is not None else cancel
    cancellation = cancellation if cancellation is not None else cancel_token
    config_settings = config_settings if config_settings is not None else config
    token = _cancellation_token(cancellation)
    _check_cancelled(token)

    absolute_source = os.path.abspath(os.fspath(source_dir))
    _validate_source_directory(absolute_source)

    if isinstance(hooks, str) and hooks in {'wheel', 'sdist', 'editable'} and distribution is None:
        distribution = hooks
        hooks = None

    pyproject_path = os.path.join(absolute_source, 'pyproject.toml')
    pyproject = _read_pyproject_toml(pyproject_path)
    build_system = _parse_build_system_table(pyproject)
    backend_path = tuple(build_system.get('backend-path', ()))
    if backend_path:
        from ._builder import _validate_backend_path

        _validate_backend_path(absolute_source, list(backend_path))
    normalized_backend_path = _normalize_backend_paths(absolute_source, backend_path)

    config = normalize_config_settings(config_settings)
    planned_hooks = _plan_hooks(hooks, distribution)
    snapshot = _scan_or_materialize(absolute_source, cancellation=token)
    project_dependencies = _static_project_dependencies(pyproject)

    canonical = {
        'schema_version': SCHEMA_VERSION,
        'backend_name': build_system['build-backend'],
        'backend_path': list(normalized_backend_path),
        'requires': list(build_system['requires']),
        'hooks': [hook.name for hook in planned_hooks],
        'config_settings': _config_to_json(config),
        'project_dependencies': (
            'unknown' if project_dependencies is UNKNOWN_DEPENDENCIES else list(project_dependencies)
        ),
        'snapshot_digest': snapshot.digest,
    }
    digest = _sha256_bytes(canonical)
    return BuildPlan(
        source_dir=absolute_source,
        resolved_source_dir=os.path.realpath(absolute_source),
        backend_name=build_system['build-backend'],
        backend_path=normalized_backend_path,
        requires=tuple(build_system['requires']),
        hooks=tuple(hook.name for hook in planned_hooks),
        config_settings=config,
        snapshot=snapshot,
        plan_digest=digest,
        project_dependencies=project_dependencies,
        hook_details=planned_hooks,
        backend_path_raw=backend_path,
    )


plan_build = plan_project
create_plan = plan_project


@dataclass(frozen=True)
class FrozenSource:
    """Private materialized copy that backend subprocesses are asked to use."""

    path: str
    digest: str
    content_digest: str
    _owns_directory: bool = field(default=True, compare=False)
    _finalizer: Any = field(default=None, compare=False, repr=False)

    @classmethod
    def materialize(cls, plan: BuildPlan, cancellation: CancellationLike = None) -> FrozenSource:
        token = _cancellation_token(cancellation)
        _check_cancelled(token)
        destination = tempfile.mkdtemp(prefix='build-approval-freeze-')
        try:
            snapshot = _scan_or_materialize(plan.source_dir, destination, token)
            if snapshot.digest != plan.snapshot.digest:
                changed = plan.snapshot.changed_entries_from(snapshot)
                msg = 'Source changed after planning; refusing to materialize an outdated authorization'
                raise PlanChangedError(msg, changed)
            frozen = cls(
                path=destination,
                digest=snapshot.digest,
                content_digest=snapshot.content_digest,
            )
            finalizer = weakref.finalize(frozen, shutil.rmtree, destination, ignore_errors=True)
            object.__setattr__(frozen, '_finalizer', finalizer)
            return frozen
        except BaseException:
            shutil.rmtree(destination, ignore_errors=True)
            raise

    def verify(self, plan: BuildPlan) -> None:
        current = _scan_or_materialize(self.path)
        if current.content_digest != plan.snapshot.content_digest:
            msg = 'Frozen source snapshot has been modified; authorization is no longer valid'
            raise PlanChangedError(msg)

    def cleanup(self) -> None:
        finalizer = self._finalizer
        if finalizer is not None and finalizer.alive:
            finalizer()
        elif self._owns_directory:
            shutil.rmtree(self.path, ignore_errors=True)

    close = cleanup

    def __enter__(self) -> FrozenSource:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.cleanup()


@dataclass(frozen=True)
class DependencyGrant:
    """Explicit approval for one exact set of dynamically resolved requirements."""

    authorization_digest: str
    hook_name: str
    requirements: tuple[str, ...]
    grant_digest: str


@dataclass(frozen=True)
class PlanAuthorization:
    """Capability binding selected hooks to one canonical plan and snapshot."""

    plan: BuildPlan = field(compare=False, repr=False)
    hooks: tuple[str, ...]
    plan_digest: str
    snapshot_digest: str
    source_dir: str
    authorization_digest: str
    frozen_source: FrozenSource | None = field(default=None, compare=False, repr=False)

    @property
    def digest(self) -> str:
        return self.authorization_digest

    def allows(self, hook_name: str) -> bool:
        return hook_name in self.hooks

    def verify(self) -> None:
        canonical = {
            'schema_version': SCHEMA_VERSION,
            'plan_digest': self.plan.plan_digest,
            'snapshot_digest': self.plan.snapshot_digest,
            'hooks': sorted(self.hooks),
            'source_dir': os.path.normcase(os.path.abspath(self.source_dir)),
            'resolved_source_dir': os.path.normcase(os.path.realpath(os.path.abspath(self.source_dir))),
        }
        expected_digest = _sha256_bytes(canonical)
        if (
            self.authorization_digest != expected_digest
            or self.plan_digest != self.plan.plan_digest
            or self.snapshot_digest != self.plan.snapshot_digest
        ):
            msg = 'Authorization digest does not match its normalized plan, hooks, or source snapshot'
            raise AuthorizationError(msg)

    def require_hook(self, hook_name: str) -> None:
        if not self.allows(hook_name):
            msg = f'Hook {hook_name!r} was not explicitly authorized; authorized hooks: {list(self.hooks)!r}'
            raise HookNotAuthorizedError(msg)

    def builder(self, **kwargs: Any) -> ApprovedProjectBuilder:
        return ApprovedProjectBuilder(self.plan, self, **kwargs)

    def close(self) -> None:
        if self.frozen_source is not None:
            self.frozen_source.cleanup()

    def __enter__(self) -> PlanAuthorization:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


Approval = PlanAuthorization
Authorization = PlanAuthorization
BuildApproval = PlanAuthorization


def authorize_plan(
    plan: BuildPlan,
    hooks: str | Sequence[str] | Callable[[BuildPlan], bool | None] | bool | None = None,
    *,
    approved_hooks: str | Sequence[str] | None = None,
    allowed_hooks: str | Sequence[str] | None = None,
    approver: Callable[[BuildPlan], bool | None] | None = None,
    approved: bool | None = None,
    cancellation: CancellationLike = None,
    should_cancel: CancellationLike = None,
    cancel: CancellationLike = None,
    cancel_token: CancellationLike = None,
    freeze: bool = True,
) -> PlanAuthorization:
    """Ask an approval callback and bind its decision to the canonical plan."""

    if isinstance(hooks, bool):
        approved = hooks
        hooks = None
    if hooks is None:
        hooks = approved_hooks if approved_hooks is not None else allowed_hooks

    cancellation = cancellation if cancellation is not None else should_cancel
    cancellation = cancellation if cancellation is not None else cancel
    cancellation = cancellation if cancellation is not None else cancel_token
    token = _cancellation_token(cancellation)
    _check_cancelled(token)

    if approved is False:
        msg = 'Plan authorization was explicitly denied'
        raise AuthorizationError(msg)

    if callable(hooks) and approver is None:
        approver = hooks
        hooks = None

    if approver is not None:
        try:
            decision = approver(plan)
        except ApprovalError:
            raise
        except Exception as exception:
            msg = 'Approval callback failed; denying execution'
            raise AuthorizationError(msg) from exception
        if decision is False or decision is None:
            msg = 'Plan was not approved by the supplied callback'
            raise AuthorizationError(msg)

    selected = plan.hook_names if hooks is None else tuple(hook.name for hook in _plan_hooks(hooks, None))
    planned = set(plan.hook_names)
    not_planned = tuple(hook for hook in selected if hook not in planned)
    if not_planned:
        msg = f'Hook(s) {not_planned!r} are absent from the planned hook set; replan before authorizing them'
        raise HookNotAuthorizedError(msg)

    frozen_source = FrozenSource.materialize(plan, token) if freeze else None
    source_dir = os.path.abspath(plan.source_dir)
    canonical = {
        'schema_version': SCHEMA_VERSION,
        'plan_digest': plan.plan_digest,
        'snapshot_digest': plan.snapshot_digest,
        'hooks': sorted(selected),
        'source_dir': os.path.normcase(source_dir),
        'resolved_source_dir': os.path.normcase(os.path.realpath(source_dir)),
    }
    authorization_digest = _sha256_bytes(canonical)
    return PlanAuthorization(
        plan=plan,
        hooks=tuple(sorted(selected)),
        plan_digest=plan.plan_digest,
        snapshot_digest=plan.snapshot_digest,
        source_dir=source_dir,
        authorization_digest=authorization_digest,
        frozen_source=frozen_source,
    )


approve_plan = authorize_plan


def verify_live_plan(plan: BuildPlan, cancellation: CancellationLike = None) -> SourceSnapshot:
    """Compare the current source tree, including symlink targets, with the plan."""

    token = _cancellation_token(cancellation)
    current = _scan_or_materialize(plan.source_dir, cancellation=token)
    if current.digest != plan.snapshot.digest:
        changed = plan.snapshot.changed_entries_from(current)
        msg = f'Live source no longer matches authorization; changed entries: {changed!r}'
        raise PlanChangedError(msg, changed)
    return current


def approve_dynamic_dependencies(
    authorization: PlanAuthorization,
    requirements: Collection[str] | str,
    *,
    hook_name: str = HOOK_DEPENDENCIES_WHEEL,
    approver: Callable[[tuple[str, ...]], bool | Collection[str] | None] | None = None,
    approved: bool | Collection[str] | None = None,
    cancellation: CancellationLike = None,
) -> DependencyGrant:
    """Create an exact, authorization-bound grant for resolved dynamic deps."""

    token = _cancellation_token(cancellation)
    _check_cancelled(token)
    authorization.require_hook(hook_name)

    if isinstance(requirements, str):
        requested = (requirements,)
    else:
        requested = tuple(sorted(set(requirements)))

    if approver is not None:
        decision: bool | Collection[str] | None = approver(requested)
        if isinstance(decision, bool):
            approved = decision
        elif decision is None:
            approved = False
        else:
            approved = decision

    if approved is True:
        accepted = requested
    elif isinstance(approved, str):
        accepted = (approved,)
    elif approved is not None and approved is not False:
        accepted = tuple(sorted(set(approved)))
    else:
        msg = f'Dynamically resolved dependencies require explicit approval: {requested!r}'
        raise DependencyApprovalRequired(msg, requested)

    not_requested = tuple(item for item in accepted if item not in requested)
    if not_requested:
        msg = f'Cannot approve dependencies that were not resolved by the authorized hook: {not_requested!r}'
        raise DependencyApprovalRequired(msg)

    canonical = {
        'authorization_digest': authorization.authorization_digest,
        'hook_name': hook_name,
        'requirements': list(accepted),
    }
    return DependencyGrant(
        authorization_digest=authorization.authorization_digest,
        hook_name=hook_name,
        requirements=tuple(sorted(accepted)),
        grant_digest=_sha256_bytes(canonical),
    )


authorize_dependencies = approve_dynamic_dependencies
approve_dependencies = approve_dynamic_dependencies


def install_approved_dependencies(environment: Any, grant: DependencyGrant) -> None:
    """Install only dependencies covered by a :class:`DependencyGrant`."""

    if not grant.requirements:
        return
    install = getattr(environment, 'install', None)
    if not callable(install):
        msg = 'Isolated environment must provide an install() method'
        raise TypeError(msg)
    install(list(grant.requirements))


class ApprovedIsolatedEnvironment:
    """Environment wrapper that refuses installs without the matching approval."""

    def __init__(self, environment: Any, authorization: PlanAuthorization) -> None:
        self._environment = environment
        self._authorization = authorization
        self.installed_static: list[str] = []
        self.installed_dynamic: list[str] = []

    @property
    def python_executable(self) -> str:
        return self._environment.python_executable

    @property
    def path(self) -> str:
        return getattr(self._environment, 'path', '')

    def make_extra_environ(self) -> Mapping[str, str] | None:
        return self._environment.make_extra_environ()

    def install_static(self) -> None:
        requirements = list(self._authorization.plan.static_dependencies)
        self._environment.install(requirements)
        self.installed_static.extend(requirements)

    def install_dynamic(self, grant: DependencyGrant) -> None:
        if grant.authorization_digest != self._authorization.authorization_digest:
            msg = 'Dependency grant does not belong to this build authorization'
            raise AuthorizationError(msg)
        install_approved_dependencies(self._environment, grant)
        self.installed_dynamic.extend(grant.requirements)

    def install(self, requirements: Collection[str]) -> None:  # noqa: ARG002
        msg = (
            'Generic install() is blocked in approval mode; use install_static() after plan authorization or '
            'approve_dynamic_dependencies() followed by install_dynamic()'
        )
        raise DependencyApprovalRequired(msg)


class _GuardedHookProxy:
    """Authorize direct calls to the private pyproject-hooks caller as well."""

    def __init__(self, hook_caller: Any, builder: ApprovedProjectBuilder) -> None:
        object.__setattr__(self, '_hook_caller', hook_caller)
        object.__setattr__(self, '_builder', builder)

    def __getattr__(self, name: str) -> Any:
        attribute = getattr(object.__getattribute__(self, '_hook_caller'), name)
        if name in KNOWN_HOOKS and callable(attribute):

            def guarded(*args: Any, **kwargs: Any) -> Any:
                object.__getattribute__(self, '_builder')._check_hook_caller(name)
                return attribute(*args, **kwargs)

            return guarded
        if name == '_call_hook' and callable(attribute):
            def guarded_call(hook_name: str, *args: Any, **kwargs: Any) -> Any:
                object.__getattribute__(self, '_builder')._check_hook_caller(hook_name)
                return attribute(hook_name, *args, **kwargs)

            return guarded_call
        return attribute


class ApprovedProjectBuilder(ProjectBuilder):
    """Project builder that executes only exact authorized hooks from a frozen tree."""

    def __init__(
        self,
        plan: BuildPlan | StrPath | PlanAuthorization,
        authorization: PlanAuthorization | Callable[..., Any] | Sequence[str] | str | None = None,
        runner: SubprocessRunner = pyproject_hooks.default_subprocess_runner,
        python_executable: str = sys.executable,
        hooks: str | Sequence[str] | None = None,
        *,
        grant: PlanAuthorization | None = None,
        approved_hooks: str | Sequence[str] | None = None,
        executable: str | None = None,
        cancellation: CancellationLike = None,
        cancel: CancellationLike = None,
        cancel_token: CancellationLike = None,
        verify_live: bool = True,
    ) -> None:
        if authorization is None and grant is not None:
            authorization = grant
        if hooks is None and approved_hooks is not None:
            hooks = approved_hooks
        if isinstance(authorization, PlanAuthorization):
            pass
        elif callable(authorization):
            runner = authorization  # type: ignore[assignment]
            authorization = None
        elif isinstance(authorization, str):
            python_executable = authorization
            authorization = None
        elif isinstance(authorization, Sequence):
            hooks = authorization
            authorization = None

        if executable is not None:
            python_executable = executable
        cancellation = cancellation if cancellation is not None else cancel
        cancellation = cancellation if cancellation is not None else cancel_token

        if isinstance(plan, PlanAuthorization) and authorization is None:
            authorization = plan
            plan = authorization.plan
        elif not isinstance(plan, BuildPlan):
            planned = plan_project(plan, hooks=hooks, config_settings=None, cancellation=cancellation)
            if authorization is not None and isinstance(authorization, PlanAuthorization):
                if authorization.plan_digest != planned.plan_digest:
                    msg = 'Supplied authorization does not match the source plan'
                    raise AuthorizationError(msg)
                plan = authorization.plan
            else:
                plan = planned

        implicit_authorization = authorization is None
        if authorization is None:
            authorization = authorize_plan(plan, hooks=hooks, cancellation=cancellation)
        if authorization.plan_digest != plan.plan_digest or authorization.snapshot_digest != plan.snapshot_digest:
            msg = 'Authorization is not bound to this canonical plan and source snapshot'
            raise AuthorizationError(msg)
        if os.path.normcase(os.path.abspath(plan.source_dir)) != os.path.normcase(
            os.path.abspath(authorization.source_dir)
        ):
            msg = 'Authorization is bound to a different source directory'
            raise AuthorizationError(msg)
        authorization.verify()

        self._approval_plan = plan
        self._approval_authorization = authorization
        self._approval_cancellation = _cancellation_token(cancellation)
        self._approval_verify_live = verify_live
        self.invoked_hooks: list[str] = []
        self._preauthorized_hooks: set[str] = set()
        self.runner_calls: list[tuple[Sequence[str], str | None]] = []
        self._owns_authorization = implicit_authorization

        owns_freeze = False
        frozen = authorization.frozen_source
        if frozen is None or not os.path.isdir(frozen.path):
            frozen = FrozenSource.materialize(plan, self._approval_cancellation)
            owns_freeze = True
        self._frozen_source = frozen
        self._owns_freeze = owns_freeze

        if verify_live:
            verify_live_plan(plan, self._approval_cancellation)
        frozen.verify(plan)

        user_runner = runner
        frozen_path = frozen.path
        cancellation_token = self._approval_cancellation

        def approved_runner(
            cmd: Sequence[str],
            cwd: str | None = None,
            extra_environ: Mapping[str, str] | None = None,
        ) -> None:
            _check_cancelled(cancellation_token)
            if cwd is not None and _path_identity(cwd) != _path_identity(frozen_path):
                msg = f'Custom runner cwd {cwd!r} is not the approved frozen source {frozen_path!r}'
                raise AuthorizationError(msg)
            self.runner_calls.append((list(cmd), cwd))
            user_runner(cmd, cwd, extra_environ)

        super().__init__(
            frozen_path,
            python_executable=python_executable,
            runner=approved_runner,
        )
        self._hook = _GuardedHookProxy(self._hook, self)

    @classmethod
    def from_isolated_env(  # type: ignore[override]
        cls,
        isolation: Any,
        source_or_plan: StrPath | BuildPlan | PlanAuthorization | None = None,
        runner: SubprocessRunner = pyproject_hooks.default_subprocess_runner,
        plan: BuildPlan | None = None,
        authorization: PlanAuthorization | None = None,
        *,
        hooks: str | Sequence[str] | None = None,
        cancellation: CancellationLike = None,
        verify_live: bool = True,
    ) -> ApprovedProjectBuilder:
        # The inherited third positional parameter is ``runner``; approval callers may pass a grant there.
        if isinstance(runner, PlanAuthorization) and authorization is None:
            authorization = runner
            runner = pyproject_hooks.default_subprocess_runner
        if isinstance(source_or_plan, BuildPlan):
            plan = source_or_plan
        elif isinstance(source_or_plan, PlanAuthorization):
            authorization = source_or_plan
            plan = authorization.plan
        elif source_or_plan is not None and plan is None:
            plan = plan_project(source_or_plan, hooks=hooks, cancellation=cancellation)
        if plan is None and authorization is not None:
            plan = authorization.plan
        if plan is None:
            msg = 'A BuildPlan or source directory is required'
            raise PlanValidationError(msg)

        wrapped_runner = _wrap_approval_runner(runner, isolation)
        return cls(
            plan,
            authorization,
            hooks=hooks,
            runner=wrapped_runner,
            python_executable=isolation.python_executable,
            cancellation=cancellation,
            verify_live=verify_live,
        )

    @property
    def plan(self) -> BuildPlan:
        return self._approval_plan

    @property
    def authorization(self) -> PlanAuthorization:
        return self._approval_authorization

    @property
    def frozen_source_path(self) -> str:
        return self._frozen_source.path

    def _bind_config(self, config_settings: ConfigSettings | None) -> dict[str, str | list[str]]:
        if config_settings is not None:
            supplied = normalize_config_settings(config_settings)
            if supplied != self._approval_plan.config_settings:
                msg = 'Supplied config_settings do not match the normalized settings bound to the authorization'
                raise PlanChangedError(msg)
        return _config_for_hook(self._approval_plan.config_settings)

    def _authorize_hook(self, hook_name: str) -> None:
        _check_cancelled(self._approval_cancellation)
        self._approval_authorization.verify()
        self._approval_authorization.require_hook(hook_name)
        if self._approval_verify_live:
            verify_live_plan(self._approval_plan, self._approval_cancellation)
        self._frozen_source.verify(self._approval_plan)
        _check_cancelled(self._approval_cancellation)
        self.invoked_hooks.append(hook_name)
        self._preauthorized_hooks.add(hook_name)

    def _check_hook_caller(self, hook_name: str) -> None:
        if hook_name in self._preauthorized_hooks:
            self._preauthorized_hooks.discard(hook_name)
            self._approval_authorization.verify()
            self._approval_authorization.require_hook(hook_name)
            return
        self._authorize_hook(hook_name)

    def get_requires_for_build(
        self,
        distribution: str,
        config_settings: ConfigSettings | None = None,
    ) -> set[str]:
        hook_name = f'get_requires_for_build_{distribution}'
        bound_config = self._bind_config(config_settings)
        self._authorize_hook(hook_name)
        return super().get_requires_for_build(distribution, bound_config)

    def _call_backend(
        self,
        hook_name: str,
        outdir: StrPath,
        config_settings: ConfigSettings | None = None,
        **kwargs: str | bool,
    ) -> str:
        bound_config = self._bind_config(config_settings)
        self._authorize_hook(hook_name)
        return super()._call_backend(hook_name, outdir, bound_config, **kwargs)

    def get_requires_for_build_wheel(self, config_settings: ConfigSettings | None = None) -> set[str]:
        return self.get_requires_for_build('wheel', config_settings)

    def get_requires_for_build_sdist(self, config_settings: ConfigSettings | None = None) -> set[str]:
        return self.get_requires_for_build('sdist', config_settings)

    def resolve_and_approve_dependencies(
        self,
        environment: Any | None = None,
        *,
        distribution: str = 'wheel',
        config_settings: ConfigSettings | None = None,
        approver: Callable[[tuple[str, ...]], bool | Collection[str] | None] | None = None,
        approved: bool | Collection[str] | None = None,
    ) -> DependencyGrant:
        """Run an authorized dependency hook, then gate and optionally install results."""

        hook_name = f'get_requires_for_build_{distribution}'
        requirements = self.get_requires_for_build(distribution, config_settings)
        grant = approve_dynamic_dependencies(
            self.authorization,
            requirements,
            hook_name=hook_name,
            approver=approver,
            approved=approved,
            cancellation=self._approval_cancellation,
        )
        if environment is not None:
            if isinstance(environment, ApprovedIsolatedEnvironment):
                environment.install_dynamic(grant)
            else:
                install_approved_dependencies(environment, grant)
        return grant

    def prepare_metadata_for_build_wheel(
        self,
        metadata_directory: StrPath,
        config_settings: ConfigSettings | None = None,
    ) -> str | None:
        return self.prepare('wheel', metadata_directory, config_settings)

    def build_wheel(
        self,
        wheel_directory: StrPath,
        config_settings: ConfigSettings | None = None,
        metadata_directory: str | None = None,
    ) -> str:
        return self.build(
            'wheel',
            wheel_directory,
            config_settings,
            metadata_directory=metadata_directory,
        )

    def build_sdist(
        self,
        sdist_directory: StrPath,
        config_settings: ConfigSettings | None = None,
    ) -> str:
        return self.build('sdist', sdist_directory, config_settings)

    def execute(
        self,
        hook_name: str,
        output_directory: StrPath,
        config_settings: ConfigSettings | None = None,
        **kwargs: str | bool,
    ) -> str | None:
        """Execute a standard output-producing PEP 517 hook by its exact name."""

        if hook_name.startswith('build_'):
            distribution = hook_name.removeprefix('build_')
            return self.build(distribution, output_directory, config_settings, **kwargs)
        if hook_name.startswith('prepare_metadata_for_build_'):
            distribution = hook_name.removeprefix('prepare_metadata_for_build_')
            return self.prepare(distribution, output_directory, config_settings)
        msg = f'Hook {hook_name!r} does not produce an output basename through execute()'
        raise HookNotAuthorizedError(msg)

    def close(self) -> None:
        try:
            if self._owns_freeze:
                self._frozen_source.cleanup()
        finally:
            if self._owns_authorization:
                self._approval_authorization.close()

    def __enter__(self) -> ApprovedProjectBuilder:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _wrap_approval_runner(runner: SubprocessRunner, isolation: Any) -> SubprocessRunner:
    # Reuse build's environment-variable wrapping without importing a private name at module import time.
    from ._builder import _wrap_subprocess_runner

    return _wrap_subprocess_runner(runner, isolation)


def build_authorized(
    plan: BuildPlan | StrPath,
    authorization: PlanAuthorization | StrPath | None = None,
    output_directory: StrPath | None = None,
    *,
    output_dir: StrPath | None = None,
    distribution: str = 'wheel',
    hook: str | None = None,
    hooks: str | Sequence[str] | None = None,
    config_settings: ConfigSettings | None = None,
    runner: SubprocessRunner = pyproject_hooks.default_subprocess_runner,
    python_executable: str = sys.executable,
    isolated_environment: Any = None,
    dependency_approver: Callable[..., Any] | bool | Collection[str] | None = None,
    approve_dependencies: Callable[..., Any] | bool | Collection[str] | None = None,
    dependency_callback: Callable[..., Any] | bool | Collection[str] | None = None,
    cancellation: CancellationLike = None,
    should_cancel: CancellationLike = None,
    metadata_directory: str | None = None,
) -> str:
    """Authorize static dependencies, gate dynamic deps, and run one approved build hook."""

    if dependency_approver is None:
        dependency_approver = approve_dependencies if approve_dependencies is not None else dependency_callback

    if isinstance(authorization, (str, os.PathLike)) and output_directory is None:
        output_directory = os.fspath(authorization)
        authorization = None
    output_directory = output_directory if output_directory is not None else output_dir
    if output_directory is None:
        msg = 'output_directory is required'
        raise PlanValidationError(msg)
    if hook is not None:
        distribution = hook.removeprefix('build_') if hook.startswith('build_') else distribution
        hooks = hooks or (hook,)
    if not isinstance(plan, BuildPlan):
        plan = plan_project(plan, hooks=hooks, config_settings=config_settings, cancellation=cancellation)

    cancellation = cancellation if cancellation is not None else should_cancel
    token = _cancellation_token(cancellation)
    if authorization is None:
        authorization = authorize_plan(plan, hooks=hooks, cancellation=token)

    executable = python_executable
    build_runner = runner
    if isolated_environment is not None:
        executable = isolated_environment.python_executable
        build_runner = _wrap_approval_runner(runner, isolated_environment)
        if isinstance(isolated_environment, ApprovedIsolatedEnvironment):
            isolated_environment.install_static()
        else:
            isolated_environment.install(list(plan.static_dependencies))

    with ApprovedProjectBuilder(
        plan,
        authorization,
        runner=build_runner,
        python_executable=executable,
        cancellation=token,
    ) as builder:
        dependency_hook = f'get_requires_for_build_{distribution}'
        if authorization.allows(dependency_hook) and isolated_environment is not None:
            requirements = builder.get_requires_for_build(distribution, config_settings)
            grant = approve_dynamic_dependencies(
                authorization,
                requirements,
                hook_name=dependency_hook,
                approver=dependency_approver if callable(dependency_approver) else None,
                approved=None if callable(dependency_approver) else dependency_approver,
                cancellation=token,
            )
            if isinstance(isolated_environment, ApprovedIsolatedEnvironment):
                isolated_environment.install_dynamic(grant)
            else:
                isolated_environment.install(list(grant.requirements))

        return builder.build(
            distribution,
            output_directory,
            config_settings,
            metadata_directory=metadata_directory,
        )


AuthorizedProjectBuilder = ApprovedProjectBuilder
ApprovedBuild = ApprovedProjectBuilder
create_build_plan = plan_project
plan = plan_project
authorize = authorize_plan
approve = approve_plan
grant_authorization = authorize_plan
request_authorization = authorize_plan
execute_authorized = build_authorized
execute_authorized_build = build_authorized

ApprovalRequired = AuthorizationError
AuthorizationRequired = AuthorizationError
UnauthorizedHookError = HookNotAuthorizedError
StalePlanError = PlanChangedError
PlanMismatchError = PlanChangedError

ProjectBuilder.plan = staticmethod(plan_project)  # type: ignore[attr-defined]
ProjectBuilder.create_approval_plan = staticmethod(plan_project)  # type: ignore[attr-defined]
ProjectBuilder.build_authorized = staticmethod(build_authorized)  # type: ignore[attr-defined]


__all__ = [
    'UNKNOWN',
    'UNKNOWN_DEPENDENCIES',
    'DYNAMIC_DEPENDENCIES_UNKNOWN',
    'Approval',
    'ApprovalCancelled',
    'ApprovalError',
    'ApprovalRequired',
    'ApprovalPlan',
    'ApprovedIsolatedEnvironment',
    'ApprovedProjectBuilder',
    'ApprovedBuild',
    'Authorization',
    'AuthorizationError',
    'AuthorizedProjectBuilder',
    'BuildApproval',
    'BuildPlan',
    'CancellationToken',
    'DependencyApprovalRequired',
    'DependencyGrant',
    'FrozenSource',
    'HookNotAuthorizedError',
    'PlanAuthorization',
    'PlanChangedError',
    'PlanMismatchError',
    'PlanValidationError',
    'SourceEntry',
    'SourceSnapshot',
    'StalePlanError',
    'UnauthorizedHookError',
    'AuthorizationRequired',
    'approve_dependencies',
    'approve_dynamic_dependencies',
    'approve_plan',
    'approve',
    'authorize',
    'authorize_dependencies',
    'authorize_plan',
    'build_authorized',
    'create_build_plan',
    'create_plan',
    'execute_authorized',
    'execute_authorized_build',
    'install_approved_dependencies',
    'normalize_config_settings',
    'plan',
    'plan_build',
    'plan_project',
    'request_authorization',
    'snapshot_source',
    'verify_live_plan',
]
