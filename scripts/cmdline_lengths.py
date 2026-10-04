"""
scripts/cmdline_lengths.py, how long are the command lines on this machine.

WHY THIS EXISTS, 2026-09-13. query_processes became a fenced tool, so every
string it returns passes through sanitize.scrub_string and is cut at
MAX_STRING_LEN. 2000 was picked when the file was written, with the comment
"long enough for a real command line", and nobody ever checked that against a
real machine.

So this counts. It does not change anything and it writes nothing.

Read only. No admin needed, and it is more useful WITHOUT admin, because that
is the token the app itself runs on under the privilege split, so what this
cannot read is what the app cannot read either.

    python scripts/cmdline_lengths.py

THE ONE RULE IT FOLLOWS: a process whose command line could not be read is
counted in its own bucket and never as a short one. "I could not look" and
"it was short" are different answers and mixing them would make the cap look
safer than it is.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import psutil
except ImportError:
    print("psutil is not installed here. This has to run in the venv the app "
          "uses: python scripts/cmdline_lengths.py")
    sys.exit(1)

from core.sanitize import MAX_STRING_LEN, scrub_string

read, denied, gone, empty = [], [], [], []

for proc in psutil.process_iter(["pid", "name"]):
    try:
        cmd = proc.cmdline()
    except psutil.AccessDenied:
        denied.append(proc.info.get("name") or f"pid {proc.info.get('pid')}")
        continue
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        gone.append(proc.info.get("pid"))
        continue
    except Exception as e:
        denied.append(f"{proc.info.get('name')} ({type(e).__name__})")
        continue

    line = " ".join(cmd) if cmd else ""
    if not line:
        empty.append(proc.info.get("name") or "?")
        continue
    read.append((len(line), proc.info.get("name") or "?", line))

read.sort(reverse=True)

print()
print(f"Processes with a command line we could read: {len(read)}")
print(f"Could NOT read (access denied or an error):  {len(denied)}")
print(f"Read fine but the command line was empty:    {len(empty)}")
print(f"Gone before we got to them:                  {len(gone)}")
print()
print("Those four are kept apart on purpose. Only the first group tells you "
      "anything about the cap.")

if not read:
    print()
    print("Nothing readable, so this run says NOTHING about the right cap. "
          "It is not evidence that command lines are short.")
    sys.exit(0)

lengths = [n for n, _, _ in read]
lengths_sorted = sorted(lengths)


def pct(p):
    idx = min(len(lengths_sorted) - 1, int(round((p / 100) * len(lengths_sorted))) - 1)
    return lengths_sorted[max(0, idx)]


print()
print("LENGTH IN CHARACTERS")
print(f"  shortest {lengths_sorted[0]}")
print(f"  median   {pct(50)}")
print(f"  90th     {pct(90)}")
print(f"  99th     {pct(99)}")
print(f"  longest  {lengths_sorted[-1]}")

print()
print(f"AGAINST THE CURRENT CAP OF {MAX_STRING_LEN}")
over = [(n, name) for n, name, _ in read if n > MAX_STRING_LEN]
print(f"  over the cap: {len(over)} of {len(read)} "
      f"({100 * len(over) / len(read):.1f} percent)")
for n, name in over[:20]:
    print(f"    {n:>7}  {name}")
if len(over) > 20:
    print(f"    ,,, and {len(over) - 20} more")

print()
print("WHAT OTHER CAPS WOULD COST")
for cap in (2000, 4000, 8000, 16000):
    cut = sum(1 for n in lengths if n > cap)
    print(f"  cap {cap:>6}: {cut} command line(s) cut")

print()
print("THE TEN LONGEST, so you can see whether the tail is real software or "
      "one weird thing")
for n, name, line in read[:10]:
    print(f"  {n:>7}  {name}")
    print(f"           {line[:110]}{'...' if len(line) > 110 else ''}")

if over:
    print()
    print("WHAT THE MODEL WOULD ACTUALLY SEE for the longest one, tail only:")
    _, name, line = read[0]
    print(f"  {name}")
    print(f"  ...{scrub_string(line)[-160:]}")
    print()
    print("Note it says how many characters are missing. A cut command line "
          "never reads as a whole one.")


# THE PART THAT ACTUALLY DECIDES THE NUMBER
#
# Added after the first run. Counting how many command lines exceed the cap
# answers the wrong question on its own, and I asked the wrong one first.
#
# MAX_STRING_LEN is not the only limit. sanitize.fence caps the WHOLE tool
# result at MAX_RESULT_LEN and cuts whatever is past it, so a bigger per
# string cap does not simply give the model more, it spends a shared budget.
# Let one row have 8000 characters and the rows at the END of the list are
# what pays for it, and those are dropped without being listed anywhere.
#
# So this builds the REAL query_processes answer and weighs it, the same way
# agent_loop does: json.dumps of the envelope, then the fence.

print()
print("=" * 62)
print("WHAT THE WHOLE ANSWER WEIGHS, which is the number that decides this")
print("=" * 62)

import json
from core.sanitize import MAX_RESULT_LEN

try:
    from tools.process_monitor import list_processes
except Exception as e:
    print(f"  Could not import list_processes ({type(e).__name__}: {e}), so "
          f"the payload half of this ran NOT AT ALL. The length numbers above "
          f"still stand on their own.")
    sys.exit(0)


def scrub_at(obj, cap, depth=0):
    """
    sanitize.scrub, but with the per string cap passed in.

    The real scrub() cannot be reused here. scrub_string takes the cap as a
    DEFAULT ARGUMENT, and a default is bound once when the module is imported,
    so setting sanitize.MAX_STRING_LEN from outside changes nothing and this
    whole table would have printed the same number five times while looking
    like it had measured something. Found before it printed, not after.

    The character handling is still the shipped scrub_string. Only the cap
    moves.
    """
    if depth > 12:
        return "[max depth exceeded]"
    if isinstance(obj, str):
        return scrub_string(obj, max_len=cap)
    if isinstance(obj, dict):
        return {scrub_string(str(k), max_len=200): scrub_at(v, cap, depth + 1)
                for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [scrub_at(v, cap, depth + 1) for v in obj]
    return obj

DEFAULT_LIMIT = 200          # what query_processes uses with no arguments

try:
    rows = list_processes(limit=DEFAULT_LIMIT)
except Exception as e:
    print(f"  list_processes raised {type(e).__name__}: {e}. No payload "
          f"numbers from this run. That is a failure to measure, not a "
          f"finding that the payload is small.")
    sys.exit(0)

listed = rows.get("processes") if isinstance(rows, dict) else rows
listed = listed or []

print()
print(f"query_processes with no arguments asks for up to {DEFAULT_LIMIT} rows. "
      f"This call got {len(listed)}.")
print(f"The whole result is then cut at MAX_RESULT_LEN {MAX_RESULT_LEN}.")
print()
print(f"{'cap':>8}  {'payload':>10}  {'over by':>9}  what the model ends up with")

PID_KEY = '"pid"'

for cap in (1000, 2000, 4000, 8000, 16000):
    payload = json.dumps({"result": scrub_at(rows, cap),
                          "error": None, "untrusted": True})
    size = len(payload)
    over = size - MAX_RESULT_LEN
    total_rows = payload.count(PID_KEY)
    if over <= 0:
        note = f"all {total_rows} rows, nothing dropped"
    else:
        # Rows serialise in order, so what falls past the budget is the END
        # of the list. Counting pid keys inside the kept part is a close
        # enough read of how many processes survive.
        kept = payload[:MAX_RESULT_LEN].count(PID_KEY)
        note = f"only {kept} of {total_rows} rows, the rest is cut off"
    print(f"{cap:>8}  {size:>10}  {max(0, over):>9}  {note}")

print()
print("Read the rows-surviving column, not the characters-cut column. A "
      "command line that gets shortened still tells you a process exists. A "
      "row past the budget is a process the model never hears about at all, "
      "and nothing on the screen says it was dropped.")

print()
print("Nothing was changed. This script only counts.")
