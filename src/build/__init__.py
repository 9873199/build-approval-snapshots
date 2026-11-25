"""
build - A simple, correct Python build frontend
"""

from __future__ import annotations


__lazy_modules__ = {
    f'{__spec__.parent}._builder',
    f'{__spec__.parent}._exceptions',
    f'{__spec__.parent}._types',
    f'{__spec__.parent}._util',
    f'{__spec__.parent}.approval',
}

from ._builder import ProjectBuilder
from ._exceptions import (
    ApprovalCancelled,
    ApprovalError,
    BuildBackendException,
    BuildException,
    BuildSystemTableValidationError,
    DependencyApprovalRequired,
    FailedProcessError,
    HookNotAuthorizedError,
    PlanChangedError,
    TypoWarning,
)
from .approval import (
    UNKNOWN_DEPENDENCIES,
    Approval,
    ApprovalPlan,
    ApprovedProjectBuilder,
    Authorization,
    AuthorizedProjectBuilder,
    BuildApproval,
    BuildPlan,
    CancellationToken,
    PlanAuthorization,
    approve,
    approve_dynamic_dependencies,
    authorize,
    authorize_plan,
    build_authorized,
    plan,
    plan_project,
)
from ._types import ConfigSettings as ConfigSettingsType
from ._types import Distribution as DistributionType
from ._types import SubprocessRunner as RunnerType
from ._util import check_dependency


__version__ = '1.6.1'

__all__ = [
    'UNKNOWN_DEPENDENCIES',
    'Approval',
    'ApprovalCancelled',
    'ApprovalError',
    'ApprovalPlan',
    'ApprovedProjectBuilder',
    'Authorization',
    'AuthorizedProjectBuilder',
    'BuildBackendException',
    'BuildException',
    'BuildApproval',
    'BuildPlan',
    'BuildSystemTableValidationError',
    'ConfigSettingsType',
    'CancellationToken',
    'DependencyApprovalRequired',
    'DistributionType',
    'FailedProcessError',
    'HookNotAuthorizedError',
    'PlanAuthorization',
    'PlanChangedError',
    'ProjectBuilder',
    'RunnerType',
    'TypoWarning',
    '__version__',
    'approve',
    'approve_dynamic_dependencies',
    'authorize',
    'check_dependency',
    'authorize_plan',
    'build_authorized',
    'plan',
    'plan_project',
]


def __dir__() -> list[str]:
    return __all__
