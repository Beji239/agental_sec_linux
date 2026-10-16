# core/log_format.py
# The formatter every log handler uses. Outside text (hostnames, DNS names,
# process names, feed entries) reaches log messages, and a newline in it would
# forge a log line, an escape code would drive the terminal the launcher opens.

import logging
import re

# C0 controls except tab, DEL, NEL, the Unicode line and paragraph
# separators, and the bidirectional overrides that make text read backwards.
_UNSAFE = re.compile("[\x00-\x08\x0a-\x1f\x7f\x85  "
                     "‪-‮⁦-⁩]")


def _escape(m) -> str:
    c = ord(m.group())
    return f"\\x{c:02x}" if c < 0x100 else f"\\u{c:04x}"


def one_line(text: str) -> str:
    return _UNSAFE.sub(_escape, text)


class SafeFormatter(logging.Formatter):
    """Writes control characters in the message as visible escapes. A
    traceback is added after this and keeps its own lines."""

    def formatMessage(self, record):
        record.message = one_line(record.message)
        return super().formatMessage(record)
