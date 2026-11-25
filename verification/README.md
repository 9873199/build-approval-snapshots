# Independent build approval verification
Frozen product: https://github.com/9873199/build-approval-snapshots/commit/9c6097a596a300a3ee4599e055ae5ebf4378629a

All checks below were made after the model session on unmodified frozen source. Python3.14, Windows. Create an isolated environment and install verification/requirements-lock.txt, then set PYTHONPATH to the repository src directory. Run `python -B verification/build_check.py` and `python -B verification/build_canonical_check.py`. The first reports15 passed. The second contains a changed-plan failure and an unchanged-plan passing control. It uses only public dataclasses.replace to copy the plan; no original product files are changed. The model-authored test replay is separate:129 passed,1 skipped. Backends and dependencies are harmless local fixtures. No actual package dependencies are downloaded during contract checks.

The observed defect is limited to the API's plan/authorization consistency: the copied plan uses changed config while retaining old digest fields. This is not a claim of arbitrary remote code execution or an OS sandbox.
