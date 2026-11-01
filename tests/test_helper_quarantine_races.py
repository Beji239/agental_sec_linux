"""Quarantine and restore stay inside their checked parent directories."""
import hashlib
import os
import pathlib
import stat
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from tools import action_helper as ah

tmp = pathlib.Path(tempfile.mkdtemp(prefix='quarantine-race-'))
work = tmp / 'work'
work.mkdir()
target = work / 'sample'
target.write_text('test payload\n')
target.chmod(0o750)
outside = tmp / 'outside'
outside.mkdir()
canary = outside / 'sample'
canary.write_text('outside unchanged\n')
canary.chmod(0o600)
ah.QUARANTINE_DIR = str(tmp / 'vault')
failures = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


with patch.object(ah, '_package_owner', return_value=''):
    out = ah.verb_quarantine(str(target), hashlib.sha256(target.read_bytes()).hexdigest())
    check('ordinary quarantine removes only its target', not target.exists() and canary.exists())
    moved = tmp / 'moved'
    real_open = os.open
    switched = []

    def open_then_swap(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if flags & os.O_CREAT and os.path.basename(os.fspath(path)) == 'sample':
            work.rename(moved)
            work.symlink_to(outside, target_is_directory=True)
            switched.append(True)
        return fd

    with patch.object(ah.os, 'open', side_effect=open_then_swap):
        ah.verb_restore(out['id'])
    check('the swap actually happened', bool(switched))
    check('restored bytes stay in the pinned original directory',
          (moved / 'sample').read_text() == 'test payload\n')
    check('ownership and mode apply to the restored inode',
          stat.S_IMODE((moved / 'sample').stat().st_mode) == 0o750)
    check('outside contents and mode are untouched',
          canary.read_text() == 'outside unchanged\n'
          and stat.S_IMODE(canary.stat().st_mode) == 0o600)
    work.unlink()
    moved.rename(work)

    before, real_unlink = target.read_bytes(), os.unlink
    moved = tmp / 'moved-again'

    def swap_then_unlink(path, *args, **kwargs):
        if os.path.basename(os.fspath(path)) == 'sample':
            work.rename(moved)
            work.symlink_to(outside, target_is_directory=True)
        return real_unlink(path, *args, **kwargs)

    with patch.object(ah.os, 'unlink', side_effect=swap_then_unlink):
        ah.verb_quarantine(str(target), hashlib.sha256(before).hexdigest())
    check('quarantine removal stays in the pinned directory', not (moved / 'sample').exists())
    check('quarantine cannot unlink the outside canary after a swap',
          canary.read_text() == 'outside unchanged\n')

sys.exit(bool(failures))
