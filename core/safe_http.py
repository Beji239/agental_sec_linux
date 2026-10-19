"""
Outbound HTTP that a redirect cannot turn against this network.

A feed or lookup host that is compromised, or simply answers with a redirect,
could otherwise send this app's request to the router, the dashboard on
127.0.0.1 or another device on the LAN. Redirects here may go only to public
addresses, and a request that carries a key may not be redirected to another
host at all. The first address is the caller's choice and is not checked, so
a local model server or search instance still works.
"""
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


class RedirectRefused(requests.exceptions.InvalidURL):
    """A redirect to a local address, or a keyed request leaving its host."""


def is_local(host: str) -> bool:
    """True when any address the name resolves to is not a public one, or
    when it does not resolve at all."""
    if not host:
        return True
    try:
        addrs = {ipaddress.ip_address(host.strip("[]"))}
    except ValueError:
        try:
            addrs = {ipaddress.ip_address(info[4][0].split("%")[0])
                     for info in socket.getaddrinfo(host, None)}
        except (OSError, ValueError):
            return True
    return not addrs or any(not a.is_global for a in addrs)


MAX_REDIRECTS = 10
# Never carried to another host.
KEY_HEADERS = {"authorization", "proxy-authorization", "cookie", "key",
               "apikey", "api-key", "x-api-key"}


def _check(origin_url: str, target_url: str, same_host: bool):
    parts, origin = urlsplit(target_url), urlsplit(origin_url)
    if parts.scheme not in ("http", "https"):
        raise RedirectRefused(f"redirect to {parts.scheme}: refused")
    if same_host and parts.netloc.lower() != origin.netloc.lower():
        raise RedirectRefused(
            f"{origin.hostname} redirected a request carrying a key to "
            f"{parts.hostname}; refused, the key stays with its host")
    if is_local(parts.hostname):
        raise RedirectRefused(
            f"{origin.hostname} redirected to {parts.hostname}, a local or "
            f"private address; refused")


def _send(method: str, url: str, same_host: bool, kwargs: dict):
    """Each hop through requests.get or requests.post, checked before it is
    taken. requests' own rules decide the method of the next hop."""
    kwargs = dict(kwargs, allow_redirects=False)
    for _ in range(MAX_REDIRECTS + 1):
        call = requests.post if method == "POST" else requests.get
        resp = call(url, **kwargs)
        if not getattr(resp, "is_redirect", False):
            return resp
        target = urljoin(url, resp.headers.get("location", ""))
        _check(url, target, same_host)
        resp.close()
        code = resp.status_code
        if method == "POST" and code in (301, 302, 303):
            method = "GET"
            kwargs = {k: v for k, v in kwargs.items()
                      if k not in ("data", "json", "files")}
        kwargs.pop("params", None)
        if urlsplit(target).netloc.lower() != urlsplit(url).netloc.lower():
            kwargs["headers"] = {k: v for k, v in
                                 (kwargs.get("headers") or {}).items()
                                 if k.lower() not in KEY_HEADERS}
        url = target
    raise requests.exceptions.TooManyRedirects(
        f"more than {MAX_REDIRECTS} redirects from {url}")


def get(url, same_host: bool = False, **kwargs):
    return _send("GET", url, same_host, kwargs)


def post(url, same_host: bool = False, **kwargs):
    return _send("POST", url, same_host, kwargs)
