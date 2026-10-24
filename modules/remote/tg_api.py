# modules/remote/tg_api.py
# A small Telegram Bot API client. Long polling over one kept-open HTTPS
# connection, so the bot only ever connects out and does not open a new
# connection on every poll.

import html
import http.client
import json
import re
import ssl
import threading
import urllib.parse

DEFAULT_BASE = "https://api.telegram.org"


class TelegramError(Exception):
    def __init__(self, status: int, description: str):
        super().__init__(f"{status}: {description}")
        self.status = status
        self.description = description


class Telegram:
    def __init__(self, token: str, base: str = None):
        self._token = token
        url = urllib.parse.urlsplit(base or DEFAULT_BASE)
        self._https = url.scheme == "https"
        self._host = url.hostname
        self._port = url.port
        self._local = threading.local()
        self._ctx = ssl.create_default_context() if self._https else None

    def _conn(self, timeout: float):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self._https:
                conn = http.client.HTTPSConnection(self._host, self._port,
                                                   timeout=timeout,
                                                   context=self._ctx)
            else:
                conn = http.client.HTTPConnection(self._host, self._port,
                                                  timeout=timeout)
            self._local.conn = conn
        conn.timeout = timeout
        if conn.sock is not None:
            conn.sock.settimeout(timeout)
        return conn

    def close(self):
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def call(self, method: str, params: dict = None, timeout: float = 20.0):
        body = json.dumps(params or {}).encode()
        path = f"/bot{self._token}/{method}"
        for attempt in (1, 2):
            conn = self._conn(timeout)
            try:
                conn.request("POST", path, body=body,
                             headers={"Content-Type": "application/json",
                                      "Connection": "keep-alive"})
                resp = conn.getresponse()
                raw = resp.read()
                break
            except (http.client.RemoteDisconnected, BrokenPipeError,
                    ConnectionResetError, http.client.CannotSendRequest):
                # The server closed the kept-open connection; one fresh try.
                self.close()
                if attempt == 2:
                    raise
            except Exception:
                self.close()
                raise
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            raise TelegramError(resp.status, "the answer was not JSON")
        if not data.get("ok"):
            raise TelegramError(data.get("error_code") or resp.status,
                                str(data.get("description") or "no reason given"))
        return data.get("result")

    def get_me(self):
        return self.call("getMe")

    def get_updates(self, offset: int = None, wait: int = 50):
        params = {"timeout": wait, "allowed_updates": ["message", "callback_query"]}
        if offset is not None:
            params["offset"] = offset
        return self.call("getUpdates", params, timeout=wait + 15)

    def send(self, chat_id: int, text: str, reply_markup: dict = None):
        params = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": True}
        if len(text) > 4000:
            # Cutting could split a tag, so a long one goes out as plain text.
            plain = html.unescape(re.sub(r"<[^>]+>", "", text))
            params.update(text=plain[:4000], parse_mode=None)
            params.pop("parse_mode")
        if reply_markup is not None:
            params["reply_markup"] = reply_markup
        return self.call("sendMessage", params)

    def answer_button(self, query_id: str):
        """Stops the spinner on a pressed button."""
        return self.call("answerCallbackQuery", {"callback_query_id": query_id})

    def delete(self, chat_id: int, message_id: int):
        """Takes a PIN or code out of the chat once it has been read."""
        return self.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
