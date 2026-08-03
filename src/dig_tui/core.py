"""Pure logic for dig-tui: input validation, command building, output parsing, exports.

Everything in this module is free of Textual and of I/O against the terminal, so it can be
unit tested directly. The security-critical decisions all live here rather than in the UI.
"""

from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

SETTINGS_FILE = Path.home() / ".dig-tui-settings.json"

#: Mode for the settings file. It records the last domain queried, which is lookup history;
#: 0644 would expose that to every other account on the host.
SETTINGS_MODE = 0o600

RECORD_TYPES: tuple[tuple[str, str], ...] = (
    ("A", "A"),
    ("AAAA", "AAAA"),
    ("ANY", "ANY"),
    ("CAA", "CAA"),
    ("CNAME", "CNAME"),
    ("DNSKEY", "DNSKEY"),
    ("DS", "DS"),
    ("HTTPS", "HTTPS"),
    ("MX", "MX"),
    ("NAPTR", "NAPTR"),
    ("NS", "NS"),
    ("PTR", "PTR"),
    ("SOA", "SOA"),
    ("SRV", "SRV"),
    ("SSHFP", "SSHFP"),
    ("SVCB", "SVCB"),
    ("TLSA", "TLSA"),
    ("TXT", "TXT"),
)

DNS_SERVERS: tuple[tuple[str, str], ...] = (
    ("System Default", "default"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1"),
    ("Google (8.8.8.8)", "8.8.8.8"),
    ("Quad9 (9.9.9.9)", "9.9.9.9"),
    ("OpenDNS (208.67.222.222)", "208.67.222.222"),
    ("Custom", "custom"),
)

VALID_RECORD_TYPES = frozenset(value for _, value in RECORD_TYPES)
VALID_DNS_SERVERS = frozenset(value for _, value in DNS_SERVERS)

DEFAULT_SETTINGS: dict[str, Any] = {
    "domain": "",
    "record_type": "A",
    "dns_server": "default",
    "custom_dns": "",
    "reverse": False,
    "dnssec": False,
}

#: Query timeout per attempt, and number of attempts. `dig` defaults to 5s x 3 tries = up to
#: 15 seconds; we bound it tighter and the caller also enforces a hard wall-clock timeout.
DEFAULT_TIMEOUT = 3
DEFAULT_TRIES = 2

#: A DNS label: letters, digits, hyphen and underscore (underscore is needed for service
#: names such as `_dmarc` and `_sip._tcp`). A label may not begin or end with a hyphen.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")

_SECTION_RE = re.compile(r"^;; (?P<name>QUESTION|ANSWER|AUTHORITY|ADDITIONAL) SECTION:")

EXPORT_FIELDS: tuple[str, ...] = ("section", "name", "ttl", "class", "type", "data")

#: Characters that make a spreadsheet treat a cell as a formula rather than text.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class ValidationError(ValueError):
    """Raised when user input is rejected before it can reach the `dig` argv."""


def validate_query_name(value: str) -> str:
    """Validate a domain name (or IP literal, for reverse lookups) for use as a dig query.

    The important property is that nothing resembling a command-line option can get through.
    `dig` parses positional arguments as options and accepts getopt-style bundling, so a bare
    ``-f/etc/passwd`` in a single argv element makes it read that file in batch mode and emit
    one DNS query per line. Combined with a leading ``@`` to choose the nameserver, that is a
    file-exfiltration primitive.

    Args:
        value: Raw text from the domain input.

    Returns:
        The cleaned query name.

    Raises:
        ValidationError: If the value is empty, looks like an option, or is not a plausible
            domain name or IP address.
    """
    name = value.strip()
    if not name:
        raise ValidationError("Enter a domain name.")
    if name.startswith("-"):
        raise ValidationError("Domain may not start with '-' (that would be read as a dig option).")
    if name.startswith("@"):
        raise ValidationError("Domain may not start with '@'. Use the DNS server selector instead.")
    if any(ch.isspace() for ch in name):
        raise ValidationError("Domain may not contain whitespace.")
    if len(name) > 253:
        raise ValidationError("Domain is longer than the 253-character maximum.")

    # An IP literal is valid input for a reverse lookup.
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return name

    labels = name.rstrip(".").split(".")
    if not labels or any(not _LABEL_RE.match(label) for label in labels):
        raise ValidationError(f"{name!r} is not a valid domain name.")
    return name


def validate_dns_server(value: str) -> str:
    """Validate a custom nameserver address.

    Only IP literals are accepted. The field is labelled "Custom IP", and restricting it to
    addresses means the value can never be mistaken for anything else on the command line.

    Args:
        value: Raw text from the custom DNS input.

    Returns:
        The cleaned IP address.

    Raises:
        ValidationError: If the value is empty or is not an IPv4/IPv6 literal.
    """
    server = value.strip()
    if not server:
        raise ValidationError("Enter an IP address for the custom DNS server.")
    try:
        ipaddress.ip_address(server)
    except ValueError:
        raise ValidationError(f"{server!r} is not a valid IPv4 or IPv6 address.") from None
    return server


def validate_record_type(value: str) -> str:
    """Validate a record type against the known-good list.

    Args:
        value: Record type such as ``"A"`` or ``"MX"``.

    Returns:
        The upper-cased record type.

    Raises:
        ValidationError: If the type is not one this app offers.
    """
    record_type = str(value).strip().upper()
    if record_type not in VALID_RECORD_TYPES:
        raise ValidationError(f"Unknown record type {value!r}.")
    return record_type


def build_dig_command(
    name: str,
    record_type: str = "A",
    server: str | None = None,
    *,
    reverse: bool = False,
    dnssec: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    tries: int = DEFAULT_TRIES,
) -> list[str]:
    """Build the argv for a dig invocation.

    The query name is always passed via ``-q`` and the type via ``-t``, never positionally.
    That is a structural defence: given ``-q``, dig treats the following value strictly as a
    name and refuses it if malformed, instead of parsing it as an option. Validation runs
    first, so this is the second of two independent layers.

    Args:
        name: Domain name, or IP address when ``reverse`` is set.
        record_type: DNS record type to request. Ignored when ``reverse`` is set.
        server: Nameserver IP to query, or ``None``/``"default"`` for the system resolver.
        reverse: Perform a reverse lookup (``dig -x``) instead of a forward query.
        dnssec: Request DNSSEC records (``+dnssec``).
        timeout: Seconds dig waits for each attempt.
        tries: Number of UDP attempts.

    Returns:
        The argv list, safe to pass to ``subprocess``/``asyncio`` without a shell.

    Raises:
        ValidationError: If any input fails validation.
    """
    query = validate_query_name(name)
    cmd = ["dig"]

    if server and server != "default":
        cmd.append(f"@{validate_dns_server(server)}")

    if reverse:
        try:
            ipaddress.ip_address(query)
        except ValueError:
            raise ValidationError(
                "Reverse lookup needs an IP address, not a domain name."
            ) from None
        cmd += ["-x", query]
    else:
        # `-q`/`-t` rather than positional args: see the docstring above.
        cmd += ["-q", query, "-t", validate_record_type(record_type)]

    cmd.append(f"+time={max(1, int(timeout))}")
    cmd.append(f"+tries={max(1, int(tries))}")
    if dnssec:
        cmd.append("+dnssec")
    return cmd


def parse_sections(output: str) -> dict[str, list[dict[str, str]]]:
    """Parse the record sections out of dig's textual output.

    Args:
        output: Raw stdout from dig.

    Returns:
        A mapping of section name (``ANSWER``, ``AUTHORITY``, ``ADDITIONAL``) to the list of
        records found in it. Sections with no records are omitted.
    """
    sections: dict[str, list[dict[str, str]]] = {}
    current: str | None = None

    for line in output.splitlines():
        header = _SECTION_RE.match(line)
        if header:
            # The QUESTION section has a different shape (`;name  class  type`) and carries no
            # record data, so it is not collected here.
            current = header.group("name")
            continue
        if current is None:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            current = None
            continue
        parts = re.split(r"\s+", stripped, maxsplit=4)
        if len(parts) >= 5:
            sections.setdefault(current, []).append(
                {
                    "section": current,
                    "name": parts[0],
                    "ttl": parts[1],
                    "class": parts[2],
                    "type": parts[3],
                    "data": parts[4],
                }
            )
    return sections


def flatten_sections(sections: dict[str, list[dict[str, str]]]) -> list[dict[str, str]]:
    """Flatten parsed sections into a single ordered list of records.

    Args:
        sections: Output of :func:`parse_sections`.

    Returns:
        Records ordered ANSWER, then AUTHORITY, then ADDITIONAL.
    """
    records: list[dict[str, str]] = []
    for section in ("ANSWER", "AUTHORITY", "ADDITIONAL"):
        records.extend(sections.get(section, []))
    return records


def escape_csv_field(value: Any) -> str:
    """Neutralise spreadsheet formula injection in an exported cell.

    DNS record data is controlled by whoever operates the queried zone, and the wire format
    permits bytes that dig prints unescaped. A CNAME target beginning with ``=`` becomes a
    live formula when the CSV is opened in Excel or LibreOffice. Prefixing with an apostrophe
    forces the cell to be read as text.

    Args:
        value: The cell value.

    Returns:
        The value, prefixed with ``'`` if it would otherwise be parsed as a formula.
    """
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def write_csv(path: Path, records: Sequence[dict[str, str]]) -> None:
    """Write records to a CSV file with formula injection neutralised.

    Args:
        path: Destination file.
        records: Records to write.

    Raises:
        OSError: If the file cannot be written.
    """
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=EXPORT_FIELDS)
        writer.writeheader()
        for record in records:
            writer.writerow(
                {field: escape_csv_field(record.get(field, "")) for field in EXPORT_FIELDS}
            )


def load_settings(path: Path = SETTINGS_FILE) -> dict[str, Any]:
    """Load persisted settings, falling back to defaults for anything unusable.

    The file is treated as untrusted: a tampered or corrupt file must not crash the app at
    startup, and must not smuggle a value into the domain field that has not been validated.
    Values that fail their allowlist are dropped rather than repaired.

    Args:
        path: Settings file location.

    Returns:
        A settings dict containing exactly the keys in :data:`DEFAULT_SETTINGS`.
    """
    settings = dict(DEFAULT_SETTINGS)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return settings
    if not isinstance(raw, dict):
        return settings

    domain = raw.get("domain")
    if isinstance(domain, str):
        try:
            settings["domain"] = validate_query_name(domain)
        except ValidationError:
            settings["domain"] = ""

    record_type = raw.get("record_type")
    if isinstance(record_type, str) and record_type in VALID_RECORD_TYPES:
        settings["record_type"] = record_type

    dns_server = raw.get("dns_server")
    if isinstance(dns_server, str) and dns_server in VALID_DNS_SERVERS:
        settings["dns_server"] = dns_server

    custom_dns = raw.get("custom_dns")
    if isinstance(custom_dns, str):
        try:
            settings["custom_dns"] = validate_dns_server(custom_dns)
        except ValidationError:
            settings["custom_dns"] = ""

    for flag in ("reverse", "dnssec"):
        if isinstance(raw.get(flag), bool):
            settings[flag] = raw[flag]

    return settings


def save_settings(settings: dict[str, Any], path: Path = SETTINGS_FILE) -> None:
    """Persist settings atomically with owner-only permissions.

    Written to a temporary file in the same directory and then renamed, so an interrupted
    write cannot leave a truncated file behind.

    Args:
        settings: Values to persist; only known keys are written.
        path: Settings file location.

    Raises:
        OSError: If the file cannot be written.
    """
    payload = {key: settings.get(key, default) for key, default in DEFAULT_SETTINGS.items()}
    directory = path.parent
    directory.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(directory), prefix=".dig-tui-", suffix=".tmp")
    try:
        os.fchmod(fd, SETTINGS_MODE)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def summarise(output: str) -> str:
    """Extract a one-line status summary from dig output.

    Args:
        output: Raw stdout from dig.

    Returns:
        A short summary such as ``"NOERROR - 2 answer(s) in 24 ms"``, or an empty string if
        the output carries no recognisable header.
    """
    status = re.search(r"status:\s*([A-Z]+)", output)
    if not status:
        return ""
    parts = [status.group(1)]
    counts = re.search(r"ANSWER:\s*(\d+)", output)
    if counts:
        parts.append(f"{counts.group(1)} answer(s)")
    elapsed = re.search(r"Query time:\s*(\d+)\s*msec", output)
    if elapsed:
        parts.append(f"{elapsed.group(1)} ms")
    return " - ".join([parts[0], ", ".join(parts[1:])]) if len(parts) > 1 else parts[0]


def iter_export_rows(records: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    """Normalise records to the export field set.

    Args:
        records: Parsed records.

    Returns:
        Records containing exactly :data:`EXPORT_FIELDS`.
    """
    return [{field: record.get(field, "") for field in EXPORT_FIELDS} for record in records]
