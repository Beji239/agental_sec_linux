"""Run the installer's real credential setup in a temporary folder only."""
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
source = (ROOT / 'scripts/install.sh').read_text()
env_get = next(line for line in source.splitlines() if line.startswith('env_get()'))
start = source.index('env_set() {')
end = source.index('# 5. Keys in .env', start)
functions = source[start:end]
start = source.index('step "Keys"\n')
end = source.index('if [[ -n "$(env_get AGENTAL_API_KEY)" ]]', start)
fragment = source[start:end]
program = 'set -uo pipefail\nstep() { :; }\nok() { :; }\n' + env_get + '\n' + functions + fragment
failures = []


def check(label, ok):
    print(f"{'PASS' if ok else 'FAIL'} {label}")
    if not ok:
        failures.append(label)


with tempfile.TemporaryDirectory() as folder:
    env_file = pathlib.Path(folder) / '.env'
    env_file.write_text('AGENTAL_APP_API_KEY=example-read-key\n')
    env_file.chmod(0o600)

    def run():
        subprocess.run(['bash', '-c', program], cwd=folder, check=True,
                       capture_output=True, text=True, timeout=20)
        return dict(line.split('=', 1) for line in env_file.read_text().splitlines() if '=' in line)

    first = run()
    check('existing integration key is preserved', first['AGENTAL_APP_API_KEY'] == 'example-read-key')
    check('private dashboard key is generated separately',
          len(first['AGENTAL_DASHBOARD_KEY']) == 64
          and first['AGENTAL_DASHBOARD_KEY'] != first['AGENTAL_APP_API_KEY'])
    check('running the installer again keeps both keys', run() == first)
    env_file.write_text('AGENTAL_APP_API_KEY=example-read-key\nAGENTAL_DASHBOARD_KEY=example-read-key\n')
    check('reused credentials are separated', run()['AGENTAL_DASHBOARD_KEY'] != 'example-read-key')
    env_file.write_text('AGENTAL_APP_API_KEY=' + 'a' * 64 + '\nAGENTAL_DASHBOARD_KEY=' + 'A' * 64 + '\n')
    check('case changes cannot disguise a reused credential', run()['AGENTAL_DASHBOARD_KEY'].lower() != 'a' * 64)
sys.exit(bool(failures))
