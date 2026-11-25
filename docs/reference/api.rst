###################
 API Documentation
###################

build provides a Python API for programmatic use in build tools, CI systems, and automation scripts.

.. note::

    When not using an isolated environment, the build backend must be installed in the current environment. When using
    :class:`DefaultIsolatedEnv <build.env.DefaultIsolatedEnv>`, you must explicitly install build dependencies into the
    isolated environment via :meth:`~build.env.DefaultIsolatedEnv.install` before calling
    :meth:`~build.ProjectBuilder.build` — the environment is created empty.

*************
 Basic Usage
*************

Building a package programmatically:

.. code-block:: python

    from build import ProjectBuilder

    builder = ProjectBuilder("path/to/project")
    builder.build("wheel", "dist/")

Building both sdist and wheel:

.. code-block:: python

    from build import ProjectBuilder

    builder = ProjectBuilder(".")
    builder.build("sdist", "dist/")
    builder.build("wheel", "dist/")

Using an isolated environment:

``DefaultIsolatedEnv`` creates a clean virtual environment, but it is initially empty. You must install the project's
build dependencies before invoking the backend:

.. code-block:: python

    from build import ProjectBuilder
    from build.env import DefaultIsolatedEnv

    with DefaultIsolatedEnv() as env:
        builder = ProjectBuilder.from_isolated_env(env, ".")
        # Install build-system.requires (e.g., flit-core, setuptools, ...)
        env.install(builder.build_system_requires)
        # Install additional backend dependencies for the target distribution
        env.install(builder.get_requires_for_build("wheel"))
        builder.build("wheel", "dist/")

Pass ``path`` to ``DefaultIsolatedEnv`` to use a fixed location. The directory must be empty; it is removed when the
``with`` block exits cleanly and kept when the ``with`` block raises.

``ProjectBuilder`` on its own uses the current environment. The ``runner`` argument customizes subprocess execution.

Getting package metadata:

:meth:`~build.ProjectBuilder.metadata_path` may build a wheel if the backend has no metadata hook. See
:ref:`read-wheel-metadata` for the fallback behavior and the equivalent CLI commands.

.. code-block:: python

    from build import ProjectBuilder
    import tempfile

    builder = ProjectBuilder(".")
    with tempfile.TemporaryDirectory() as tmpdir:
        metadata_dir = builder.metadata_path(tmpdir)
        # Read METADATA file from metadata_dir to extract package info

Accessing build dependencies:

.. code-block:: python

    from build import ProjectBuilder

    builder = ProjectBuilder(".")
    requires = builder.build_system_requires
    print(f"Build requires: {requires}")

    # Get additional dependencies for building a wheel
    wheel_requires = builder.get_requires_for_build("wheel")
    print(f"Wheel build requires: {wheel_requires}")

Handling errors:

.. code-block:: python

    from build import ProjectBuilder
    from build import BuildException

    try:
        builder = ProjectBuilder(".")
        builder.build("wheel", "dist/")
    except BuildException as e:
        print(f"Build failed: {e}")

**********************
 Approved execution
**********************

Use :func:`build.plan_project` (or ``BuildPlan.create``) before trusting a
source tree.  Planning only parses ``pyproject.toml`` and reads/hash source
files; it never calls ``get_requires_for_build_*``, prepares metadata, or
imports the backend.  ``dynamic_dependencies`` is ``None`` and
``dynamic_dependency_state`` is ``"unknown"``; the stricter
``UNKNOWN_DEPENDENCIES`` sentinel is also available.  Neither representation
is an empty set that would make unresolved dependencies look complete.

.. code-block:: python

    from build import BuildPlan

    plan = BuildPlan.create(
        "path/to/project",
        hooks=["get_requires_for_build_wheel", "build_wheel"],
        config_settings={"debug": "false"},
    )
    print(plan.backend_name, plan.backend_path, plan.static_dependencies)
    print(plan.hooks, plan.file_digests, plan.dynamic_dependencies)

An authorization binds the canonical plan digest, normalized configuration,
selected hook names, source snapshot digest, and source location.
``authorize_plan`` materializes a private temporary copy of the complete
snapshot.  :class:`~build.ApprovedProjectBuilder` rechecks the live tree and
the private copy before every hook and starts ``pyproject-hooks`` with the
private copy as ``source_dir`` and ``backend-path`` root.

The live recheck gives a clear :class:`~build.PlanChangedError` when
``pyproject.toml``, backend-path contents, or symlink targets changed.  A
change in the final check-to-``exec`` window cannot change what the backend
process imports because the subprocess runs against the materialized copy, not
the original directory.  This is copy-based integrity freezing, not an
operating-system sandbox: approved code can still access absolute paths, the
network, and processes as the current user.

.. code-block:: python

    from build import ApprovedProjectBuilder, authorize_plan

    authorization = authorize_plan(plan, hooks=["build_wheel"])
    with ApprovedProjectBuilder(plan, authorization) as builder:
        builder.build_wheel("dist/")

Hook grants are exact.  A metadata-only grant never silently invokes
``build_wheel``; if the optional metadata hook is missing, the strict approved
builder raises :class:`~build.HookNotAuthorizedError` instead of falling back.

For isolated builds, static ``build-system.requires`` are part of the approved
plan.  Dependencies returned by an authorized
``get_requires_for_build_*`` hook are still dynamic: pass the result to
:func:`~build.approve_dynamic_dependencies` and install only the returned
:class:`~build.DependencyGrant`, or use
:class:`~build.ApprovedIsolatedEnvironment` to block generic installs.

.. code-block:: python

    from build import approve_dynamic_dependencies

    requirements = builder.get_requires_for_build_wheel()
    dependencies = approve_dynamic_dependencies(
        authorization,
        requirements,
        approver=lambda requirements: True,  # replace with a real prompt/policy
    )
    env.install(list(dependencies.requirements))

Custom runners remain supported.  The approved builder wraps them and verifies
that their ``cwd`` is the frozen snapshot; runners must still honor that
``cwd`` as required by the standard runner contract.

***********
 Reference
***********

******************
 ``build`` module
******************

.. automodule:: build
    :members:
    :undoc-members:
    :show-inheritance:

**********************
 ``build.env`` module
**********************

.. automodule:: build.env
    :members:

**************************
 ``build.approval`` module
**************************

.. automodule:: build.approval
    :members:
    :show-inheritance:
    :undoc-members:
    :show-inheritance:

***********************
 ``build.util`` module
***********************

.. automodule:: build.util
    :members:
    :undoc-members:
    :show-inheritance:

*******
 Types
*******

.. autoclass:: build._types.SubprocessRunner()
    :special-members: __call__
