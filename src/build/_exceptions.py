from __future__ import annotations


TYPE_CHECKING = False

if TYPE_CHECKING:
    import subprocess


class BuildException(Exception):
    """
    Exception raised by ``build`` when a build cannot proceed.
    """


class BuildBackendException(Exception):
    """
    Exception raised when a backend operation fails.
    """

    def __init__(
        self,
        exception: Exception,
        description: str | None = None,
    ) -> None:
        super().__init__()
        self.exception: Exception = exception
        self._description = description

    def __str__(self) -> str:
        if self._description:
            return self._description
        return f'Backend operation failed: {self.exception!r}'


class BuildSystemTableValidationError(BuildException):
    """
    Exception raised when the ``[build-system]`` table in pyproject.toml is invalid.
    """

    def __str__(self) -> str:
        return f'Failed to validate `build-system` in pyproject.toml: {self.args[0]}'


class ApprovalError(BuildException):
    """Base class for plan, authorization, and explicit-approval failures."""


class PlanValidationError(ApprovalError, BuildSystemTableValidationError):
    """Raised when a static build plan cannot be constructed safely."""


class AuthorizationError(ApprovalError):
    """Raised when an execution is not covered by a valid authorization."""


class PlanChangedError(AuthorizationError):
    """Raised when a planned source or configuration no longer matches its grant."""


class HookNotAuthorizedError(AuthorizationError):
    """Raised when a backend hook is invoked without explicit approval."""


class DependencyApprovalRequired(AuthorizationError):
    """Raised when dynamically resolved dependencies have not been approved."""


class ApprovalCancelled(ApprovalError):
    """Raised before an approved hook starts because execution was cancelled."""


class FailedProcessError(Exception):
    """
    Exception raised when a setup or preparation operation fails.
    """

    def __init__(self, exception: subprocess.CalledProcessError, description: str) -> None:
        super().__init__()
        self.exception: subprocess.CalledProcessError = exception
        self._description = description

    def __str__(self) -> str:
        return self._description


class TypoWarning(Warning):
    """
    Warning raised when a possible typo is found.
    """
