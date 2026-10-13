# Starts coverage in every Python process of a --coverage run, children too.
# Only on PYTHONPATH when scripts/run_tests.py --coverage sets it.
import os
import sys

try:
    import coverage
    coverage.process_startup()
except Exception:
    pass

# Run the system sitecustomize this one shadows.
_here = os.path.dirname(os.path.abspath(__file__))
for _d in sys.path:
    _f = os.path.join(_d, "sitecustomize.py")
    if _d and os.path.abspath(_d) != _here and os.path.isfile(_f):
        try:
            exec(compile(open(_f, encoding="utf-8").read(), _f, "exec"), {"__name__": "sitecustomize"})
        except Exception:
            pass
        break
