"""Which cached source answers are about a node's value (Evidence → Load).

A cache key is the question a source was asked: ``GET|<url>|<params>``,
``POST|…``, ``TXT|…``, ``FORM|…`` (http_client's defaults) or a source's own
``<source>|<what>|<value>|…``. The node's value sits in it between separators
(``/``, ``|``, quotes, ``:``, ``=``, spaces). An answer is evidence for a node
when its key holds the value as a whole token. The rules:

- **Whole token.** A letter or digit right before or after the value means a
  longer token: ``11.2.3.45`` is another IP than ``1.2.3.4``, a 64-hex digest
  another hash than its first 32 characters. ``.``, ``-``, ``_`` and ``@`` join
  two parts of a hostname, an identifier or an address when a letter or digit
  follows them: ``sub.example.com``, ``example.com.evil.net``,
  ``my-example.com`` and ``user@example.com`` are other indicators than
  ``example.com``. With nothing to join they are plain punctuation: the
  wildcard queries ``%.example.com`` and ``*.example.com`` and the trailing dot
  of ``example.com.`` are about ``example.com``.
- **IPv6.** In a value shaped like an IPv6 address ``:`` joins too when a hex
  digit follows it, so ``2001:db8::1`` is found in neither ``2001:db8::1:2``
  nor ``fe80:2001:db8::1``; ``ip:2001:db8::1`` is still a hit.
- **URLs.** A value holding ``://`` must end where the key's URL ends (a quote,
  ``|``, a space, a closing bracket, a comma, the end of the key; one trailing
  ``/`` is tolerated): ``http://a.example/x/y`` and ``http://a.example/x?id=1``
  are other URLs than ``http://a.example/x``.
- **A domain inside a URL is a hit**: ``example.com`` matches a question about
  ``http://example.com/login``. The path separator cannot be told from the
  ``/`` of ``…/domain/example.com``, and the answer is about that host.
- **The question's own address is skipped**: the head of the key (verb or
  source name) and, for http_client's default keys, the host of the API. A
  node ``rdap.org`` is not evidenced by every RDAP lookup. A URL value is
  still compared with the URL that was asked.
- **Case.** Compared case-insensitively for every type. Domains, hex digests
  and addresses are case-insensitive by nature, and the sources lowercase what
  they put in their own keys (emails, usernames, company names), so a
  case-sensitive comparison would lose real answers. The cost: two URLs that
  differ only by the case of their path share their answers.
- **Percent-encoding.** Key and value are both percent-decoded before the
  comparison, so ``user%40example.com`` in a key is ``user@example.com``. A
  ``%`` followed by two hex digits is always read as an escape.
- **No pattern language.** The value is compared as plain text: ``%`` and ``_``
  (SQL wildcards) and regex metacharacters only match themselves.
- **Short values match nothing.** Under ``MIN_VALUE_LEN`` characters (an empty
  value, a letter, a two-letter country code) the lookup returns no answer
  instead of whatever the cache holds.

Pure module: no database, no I/O. ``graph_store.get_evidence_for_value`` runs
``like_pattern`` in SQL as a coarse prefilter, then ``key_mentions`` on each
candidate key.
"""
import re
from urllib.parse import unquote

MIN_VALUE_LEN = 3

LIKE_ESCAPE = "\\"

# http_client's default keys start with the verb, then the URL that was asked.
_GENERIC_VERBS = ("get", "post", "txt", "form")

# Characters that tie two parts of one token together when a letter or digit
# follows them (hostname labels, identifiers, the two sides of an address).
_JOINERS = ".-_@"

# Where a URL written in a key stops.
_URL_END = "'\"|,)}]> \t\r\n"

_HEX = "0123456789abcdef"
_IPV6_SHAPE = re.compile(r"[0-9a-f:.]+")

# Characters percent-encoding never touches: a run of them reads the same in a
# key whether the source encoded the value or not.
_UNRESERVED_RUN = re.compile(r"[A-Za-z0-9._~-]+")


def _fold(text) -> str:
    return unquote(str(text or "")).strip().lower()


def like_pattern(value) -> str | None:
    """The SQL ``LIKE`` pattern (to use with ``ESCAPE LIKE_ESCAPE``) that keeps
    every key ``key_mentions`` could accept, or None when the value is too
    short to look up. It asks for the longest run of the value that
    percent-encoding leaves alone, so encoded occurrences pass too; SQLite's
    ``LIKE`` ignores ASCII case, like the matcher."""
    needle = _fold(value)
    if len(needle) < MIN_VALUE_LEN:
        return None
    run = max(_UNRESERVED_RUN.findall(needle), key=len, default="")
    for ch in (LIKE_ESCAPE, "%", "_"):
        run = run.replace(ch, LIKE_ESCAPE + ch)
    return f"%{run}%"


def _search_start(hay: str, skip_api_host: bool) -> int:
    """Index after the part of the key that names who was asked: the head
    (verb or source name) and, after a generic verb, the API's host."""
    head, sep, _ = hay.partition("|")
    if not sep:
        return 0
    start = len(head) + 1
    if skip_api_host and head in _GENERIC_VERBS:
        scheme = hay.find("://", start)
        url_end = hay.find("|", start)
        if scheme != -1 and (url_end == -1 or scheme < url_end):
            host_end = hay.find("/", scheme + 3)
            if host_end == -1 or (url_end != -1 and host_end > url_end):
                host_end = url_end if url_end != -1 else len(hay)
            start = host_end
    return start


def _joined(hay: str, pos: int, step: int, ipv6: bool) -> bool:
    """True when the character at ``pos`` (the neighbour of a match, looking
    left with step -1 or right with step +1) continues the matched token."""
    if not 0 <= pos < len(hay):
        return False
    if hay[pos].isalnum():
        return True
    joiners = _JOINERS + (":" if ipv6 else "")
    k = pos
    while 0 <= k < len(hay) and hay[k] in joiners:
        k += step
    if k == pos or not 0 <= k < len(hay):
        return False  # a separator, or joiners with nothing behind them
    if ipv6 and set(hay[pos:k:step]) == {":"}:
        # `ip:2001:db8::1` is a field name, `fe80:2001:db8::1` a longer address.
        return hay[k] in _HEX
    return hay[k].isalnum()


def _url_continues(hay: str, end: int) -> bool:
    if end < len(hay) and hay[end] == "/":
        end += 1
    return end < len(hay) and hay[end] not in _URL_END


def key_mentions(key, value) -> bool:
    """True when the cache key holds ``value`` as a whole token (rules in the
    module docstring)."""
    needle = _fold(value)
    if len(needle) < MIN_VALUE_LEN:
        return False
    hay = _fold(key)
    ipv6 = needle.count(":") >= 2 and _IPV6_SHAPE.fullmatch(needle) is not None
    is_url = "://" in needle
    i = hay.find(needle, _search_start(hay, skip_api_host=not is_url))
    while i != -1:
        end = i + len(needle)
        right_ok = (not _url_continues(hay, end) if is_url
                    else not _joined(hay, end, 1, ipv6))
        if right_ok and not _joined(hay, i - 1, -1, ipv6):
            return True
        i = hay.find(needle, i + 1)
    return False
