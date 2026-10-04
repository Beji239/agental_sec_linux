# core/heartbeat.py
# Leave something behind to read.
#
# Written 2026-09-08, after a two hour split run where the terminal window
# would not come back from minimised, and the only way out was shutting the
# whole machine down.
#
# Reading the log afterwards, the app was completely healthy the whole time.
# It logged every two minutes, served the dashboard, answered HTTP, and never
# raised a single error. We could even prove console writes were still working,
# because logging.basicConfig puts a StreamHandler on the root logger BEFORE
# the file handler is added, so a wedged console would have blocked the file
# log too, and the file log kept going right to the second the machine went
# down.
#
# So the app was fine and the window was not. But notice how we learned that:
# by reasoning about handler ordering, after the fact, on a machine that had
# already been rebooted. That is a very thin thread to hang an answer on.
#
# This module is the thick one. Every few minutes, write down what this
# process looks like from the inside, so the next long run does not need a
# lucky deduction.
#
# It is deliberately small: memory, threads. Those are the things that go
# wrong SLOWLY, which is exactly the kind of wrong a two hour run finds and a
# two minute run never does.
#
# THE THIRD THING IT USED TO SAY, AND WHY IT IS GONE. 2026-09-25.
#
# This module carried `_helper_note()`, which asked the capability shim whether
# a privileged helper process was alive and put "HELPER GONE, <reason>" in the
# heartbeat line. THE WINDOWS TREE'S HELPER. On this platform there is no
# helper process at all: the rights question is answered by capabilities on the
# binary or by the launcher that asks for a password, so `caps.get()` returns a
# plain Capabilities with no `alive()` and the whole branch returned None on
# every beat it ever made.
#
# A branch that cannot fire is not harmless here, it is the same shape as the
# two red capability rows that this round exists to remove: it reads, to
# anybody opening the file, as a live check on a live component. The helper,
# its protocol and its client live in agental_sec_win32_reference/ now, and the
# sentence that watched for one went with them.
#
# THE PROPERTY IT WAS GUARDING IS NOT LOST. "A dead thing must be loud" is
# asserted where this platform's privileged surface actually is:
# tests/test_capability_shim.py for the shim's own refusals, and the
# readiness card's failing-polls branch (RT-4) for a module that stops working.

import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_MINUTES = 5

# Growth past this multiple of the first reading gets called out by name.
# Not a threshold with any science behind it, just a number big enough that
# ordinary warm up does not trip it and small enough to catch a real leak
# inside one evening.
LEAK_MULTIPLE = 2.0


def _rss_mb():
    """Resident memory in MB, or None when psutil is not importable."""
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / (1024.0 * 1024.0)
    except Exception:
        return None


def _uptime(started_at):
    secs = int(time.time() - started_at)
    h, rem = divmod(secs, 3600)
    m, _ = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def beat(state):
    """
    Build one heartbeat line, and a second line when something moved.

    Split out from the loop so a test can call it without waiting five
    minutes, and so it returns text rather than logging, which is the only
    way to assert on what it actually says.

    state is a plain dict the caller keeps between calls. Returns a list of
    lines, never None.
    """
    lines = []
    now_threads = {t.name for t in threading.enumerate()}
    rss = _rss_mb()

    parts = [f"up {_uptime(state['started_at'])}"]

    if rss is not None:
        first = state.get("first_rss")
        last = state.get("last_rss")
        if first is None:
            state["first_rss"] = first = rss
        bit = f"memory {rss:.1f} MB"
        if last is not None:
            bit += f" ({rss - first:+.1f} since start, {rss - last:+.1f} since last)"
        parts.append(bit)
        state["last_rss"] = rss
    else:
        parts.append("memory unknown, psutil is not installed")

    parts.append(f"{len(now_threads)} threads")

    lines.append("heartbeat: " + ", ".join(parts))

    # A thread that appears and never leaves is the classic slow failure in a
    # process like this one, and a bare count hides it. Name the newcomers.
    known = state.get("threads")
    if known is not None:
        new = sorted(now_threads - known)
        gone = sorted(known - now_threads)
        if new or gone:
            bits = []
            if new:
                bits.append("new since last beat: " + ", ".join(new))
            if gone:
                bits.append("ended: " + ", ".join(gone))
            lines.append("heartbeat threads: " + "; ".join(bits))
    state["threads"] = now_threads

    # Say the word leak out loud rather than leaving the owner to divide two numbers
    # that are four hours apart in a log file.
    if rss is not None and state.get("first_rss"):
        first = state["first_rss"]
        if first > 0 and rss / first >= LEAK_MULTIPLE and not state.get("leak_said"):
            state["leak_said"] = True
            lines.append(
                f"heartbeat: memory has more than {LEAK_MULTIPLE:g}x since this "
                f"run started, {first:.1f} MB to {rss:.1f} MB. That is what a "
                f"leak looks like. Worth a look before blaming a long run.")

    return lines


def start(interval_minutes=DEFAULT_INTERVAL_MINUTES):
    """
    Start the heartbeat on a daemon thread. Returns the thread.

    Daemon, so it never holds up a shutdown. Failures inside are logged and
    the loop carries on, because a broken heartbeat must not be the thing
    that takes down a monitor.
    """
    interval = max(1, int(interval_minutes)) * 60
    state = {"started_at": time.time()}

    def loop():
        # The first beat waits a full interval on purpose. At boot everything
        # is still settling, threads are still starting, and a reading taken
        # then is not a baseline of anything.
        while True:
            time.sleep(interval)
            try:
                for line in beat(state):
                    logger.info(line)
            except Exception as e:
                logger.warning(f"Heartbeat failed: {type(e).__name__}: {e}")

    t = threading.Thread(target=loop, name="heartbeat", daemon=True)
    t.start()
    logger.info(f"Heartbeat started, every {interval // 60} minute(s).")
    return t
