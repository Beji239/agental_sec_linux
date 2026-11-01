"""Directory swaps cannot redirect privileged text reads or replacements."""
import base64
import os
import pathlib
import stat
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools import action_helper as ah

tmp = pathlib.Path(tempfile.mkdtemp(prefix='helper-races-'))
home = tmp / 'home'
ssh = home / '.ssh'
ssh.mkdir(parents=True)
outside = tmp / 'outside'
outside.mkdir()
canary = outside / 'authorized_keys'
canary.write_text('outside must stay unchanged\n')
auth = ssh / 'authorized_keys'
auth.write_text('original\n')
auth.chmod(0o600)
failures = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


def refuses(call):
    try:
        call()
        return False
    except (OSError, ah.Refusal):
        return True


text, old = ah._open_text(str(auth))
auth.write_text('new user edit\n')
check('an intervening edit is refused', refuses(lambda: ah._rewrite(str(auth), 'replacement', old)))
check('the edit is retained', auth.read_text() == 'new user edit\n')
text, old = ah._open_text(str(auth))
moved = home / 'old-ssh'
ssh.rename(moved)
ssh.symlink_to(outside, target_is_directory=True)
check('a swapped parent cannot be read', refuses(lambda: ah._open_text(str(auth))))
check('a swapped parent cannot be rewritten', refuses(lambda: ah._rewrite(str(auth), 'replacement', old)))
check('the outside file is untouched', canary.read_text() == 'outside must stay unchanged\n')
ssh.unlink()
moved.rename(ssh)
text, old = ah._open_text(str(auth))
real_replace = os.replace


def swap_then_replace(*args, **kwargs):
    ssh.rename(moved)
    ssh.symlink_to(outside, target_is_directory=True)
    return real_replace(*args, **kwargs)


with patch.object(ah.os, 'replace', side_effect=swap_then_replace):
    ah._rewrite(str(auth), 'safe pinned replacement\n', old)
check('replacement stays in the originally opened directory',
      (moved / 'authorized_keys').read_text() == 'safe pinned replacement\n')
check('a swap immediately before replace cannot touch the outside file',
      canary.read_text() == 'outside must stay unchanged\n')
ssh.unlink()
moved.rename(ssh)
check('mode is preserved', stat.S_IMODE(auth.stat().st_mode) == 0o600)
linked = ssh / 'second-name'
os.link(auth, linked)
check('multiply linked files are refused', refuses(lambda: ah._open_text(str(auth))))
linked.unlink()
auth.write_bytes(b'x' * (ah.MAX_SMALL_FILE + 1))
check('file reads are bounded', refuses(lambda: ah._open_text(str(auth))))

blob = b'\x00\x00\x00\x0bssh-ed25519' + b'\x00\x00\x00\x20' + b'a' * 32
key = 'ssh-ed25519 ' + base64.b64encode(blob).decode() + ' example-key\n'
auth.write_text('# retained comment\n' + key)
pw = SimpleNamespace(pw_name='example', pw_dir=str(home))
records = {}


def save(kind, record):
    records['one'] = record
    return 'one'


with patch.object(ah, '_validated_user', return_value=pw), \
        patch.object(ah, '_save_undo', side_effect=save), \
        patch.object(ah, '_load_undo', side_effect=lambda uid, kind: records[uid]), \
        patch.object(ah, '_spend_undo'):
    fingerprint = ah._key_fingerprint(key)
    out = ah.verb_remove_ssh_key('example', fingerprint)
    check('ordinary key removal still works', out['removed'] and key not in auth.read_text())
    out = ah.verb_restore_ssh_key('one')
    check('ordinary key restore still works', key in auth.read_text())
check('no temporary replacement files remain', not list(ssh.glob('.agentalsec-*')))
sys.exit(bool(failures))
