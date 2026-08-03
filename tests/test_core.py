"""Tests for dig_tui.core.

The tests named ``test_s1``..``test_s4`` are regression tests for the four issues found in
the security audit; they are the acceptance criteria for those fixes.
"""

from __future__ import annotations

import csv
import json
import stat

import pytest

from dig_tui.core import (
    DEFAULT_SETTINGS,
    ValidationError,
    build_dig_command,
    escape_csv_field,
    flatten_sections,
    load_settings,
    parse_sections,
    save_settings,
    summarise,
    validate_dns_server,
    validate_query_name,
    validate_record_type,
    write_csv,
)

ANSWER_OUTPUT = """
; <<>> DiG 9.10.6 <<>> -q example.com -t A
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;example.com.\t\t\tIN\tA

;; ANSWER SECTION:
example.com.\t\t300\tIN\tA\t93.184.216.34
example.com.\t\t300\tIN\tA\t93.184.216.35

;; Query time: 24 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
"""

MULTI_SECTION_OUTPUT = """
;; ANSWER SECTION:
example.com.\t\t300\tIN\tA\t93.184.216.34

;; AUTHORITY SECTION:
example.com.\t\t3600\tIN\tNS\tns1.example.com.

;; ADDITIONAL SECTION:
ns1.example.com.\t3600\tIN\tA\t192.0.2.1

;; Query time: 10 msec
"""

NXDOMAIN_OUTPUT = """
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 999
;; QUESTION SECTION:
;nope.invalid.\t\t\tIN\tA

;; AUTHORITY SECTION:
invalid.\t\t900\tIN\tSOA\ta.root-servers.net. nstld.verisign-grs.com. 1 1800 900 604800 86400
"""


# --------------------------------------------------------------------------- S1


class TestS1ArgumentInjection:
    """dig parses positional args as options and bundles `-f<path>`, so a single argv
    element could make it read an arbitrary file in batch mode and leak it over DNS."""

    @pytest.mark.parametrize(
        "hostile",
        [
            "-f/etc/passwd",
            "-f /etc/passwd",
            "@8.8.8.8",
            "-y hmac-md5:key:secret",
            "-x",
            "--version",
        ],
    )
    def test_s1_hostile_query_names_are_rejected(self, hostile):
        with pytest.raises(ValidationError):
            validate_query_name(hostile)

    @pytest.mark.parametrize(
        "hostile",
        ["-f/etc/passwd", "@8.8.8.8", "example.com -f/etc/passwd"],
    )
    def test_s1_build_command_refuses_hostile_input(self, hostile):
        with pytest.raises(ValidationError):
            build_dig_command(hostile, "A")

    def test_s1_query_name_never_positional(self):
        """Second layer: even a valid name goes through -q, so dig cannot reinterpret it."""
        cmd = build_dig_command("example.com", "A")
        assert "-q" in cmd
        assert cmd[cmd.index("-q") + 1] == "example.com"
        assert cmd[cmd.index("-t") + 1] == "A"

    def test_s1_custom_server_cannot_carry_options(self):
        with pytest.raises(ValidationError):
            validate_dns_server("1.1.1.1 -f /etc/passwd")

    def test_s1_settings_file_cannot_smuggle_hostile_domain(self, tmp_path):
        """The audit's realistic vector: a tampered settings file replayed into the UI."""
        path = tmp_path / "settings.json"
        path.write_text(json.dumps({"domain": "-f/etc/passwd", "dns_server": "8.8.8.8"}))
        assert load_settings(path)["domain"] == ""


class TestValidation:
    @pytest.mark.parametrize(
        "name",
        [
            "example.com",
            "example.com.",
            "sub.domain.example.com",
            "_dmarc.example.com",
            "_sip._tcp.example.com",
            "xn--bcher-kva.example",
            "1.1.1.1",
            "2606:4700:4700::1111",
        ],
    )
    def test_accepts_valid_names(self, name):
        assert validate_query_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "   ",
            "exa mple.com",
            "-bad.example.com",
            "bad-.example.com",
            "a" * 254,
            "a" * 64 + ".com",
        ],
    )
    def test_rejects_invalid_names(self, name):
        with pytest.raises(ValidationError):
            validate_query_name(name)

    @pytest.mark.parametrize("server", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::1"])
    def test_accepts_ip_servers(self, server):
        assert validate_dns_server(server) == server

    @pytest.mark.parametrize(
        "server", ["", "dns.google", "1.1.1.1.1", "999.1.1.1", "-f/etc/passwd"]
    )
    def test_rejects_non_ip_servers(self, server):
        with pytest.raises(ValidationError):
            validate_dns_server(server)

    def test_record_type_allowlist(self):
        assert validate_record_type("a") == "A"
        with pytest.raises(ValidationError):
            validate_record_type("NOTAREALTYPE")


class TestBuildCommand:
    def test_default_server_omits_at_argument(self):
        assert not any(part.startswith("@") for part in build_dig_command("example.com", "A"))

    def test_explicit_server_is_prefixed(self):
        assert "@1.1.1.1" in build_dig_command("example.com", "A", "1.1.1.1")

    def test_bounds_are_always_applied(self):
        cmd = build_dig_command("example.com", "A")
        assert any(p.startswith("+time=") for p in cmd)
        assert any(p.startswith("+tries=") for p in cmd)

    def test_reverse_lookup(self):
        cmd = build_dig_command("8.8.8.8", "A", reverse=True)
        assert cmd[cmd.index("-x") + 1] == "8.8.8.8"
        assert "-q" not in cmd

    def test_reverse_lookup_requires_an_ip(self):
        with pytest.raises(ValidationError):
            build_dig_command("example.com", "A", reverse=True)

    def test_dnssec_flag(self):
        assert "+dnssec" in build_dig_command("example.com", "A", dnssec=True)
        assert "+dnssec" not in build_dig_command("example.com", "A")


# --------------------------------------------------------------------------- S3


class TestS3CsvFormulaInjection:
    @pytest.mark.parametrize(
        "payload",
        [
            "=cmd|'/c calc'!A1",
            "+1+1",
            "-2+3",
            "@SUM(A1:A2)",
            "\t=1+1",
            "\r=1+1",
        ],
    )
    def test_s3_formula_prefixes_are_neutralised(self, payload):
        assert escape_csv_field(payload).startswith("'")

    @pytest.mark.parametrize("benign", ["93.184.216.34", "example.com.", "300", '"v=spf1 -all"'])
    def test_s3_benign_values_untouched(self, benign):
        assert escape_csv_field(benign) == benign

    def test_s3_written_csv_is_inert(self, tmp_path):
        """End-to-end: a hostile CNAME target must not survive as a live formula."""
        path = tmp_path / "out.csv"
        write_csv(
            path,
            [
                {
                    "section": "ANSWER",
                    "name": "evil.com.",
                    "ttl": "300",
                    "class": "IN",
                    "type": "CNAME",
                    "data": "=cmd|'/c calc'!A1.evil.com.",
                }
            ],
        )
        with open(path, newline="", encoding="utf-8") as handle:
            row = next(iter(csv.DictReader(handle)))
        assert row["data"] == "'=cmd|'/c calc'!A1.evil.com."
        assert not row["data"].startswith("=")


# --------------------------------------------------------------------------- S4


class TestS4Settings:
    def test_s4_file_is_owner_only(self, tmp_path):
        path = tmp_path / "settings.json"
        save_settings(dict(DEFAULT_SETTINGS), path)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    @pytest.mark.parametrize(
        "content",
        ["[1, 2]", '"a string"', "null", "123", "{not json", "", "[]"],
    )
    def test_s4_malformed_files_do_not_raise(self, tmp_path, content):
        """A JSON array previously crashed the app at startup via AttributeError."""
        path = tmp_path / "settings.json"
        path.write_text(content)
        assert load_settings(path) == DEFAULT_SETTINGS

    def test_s4_missing_file_returns_defaults(self, tmp_path):
        assert load_settings(tmp_path / "nope.json") == DEFAULT_SETTINGS

    def test_s4_wrong_types_are_dropped(self, tmp_path):
        path = tmp_path / "settings.json"
        path.write_text(json.dumps({"record_type": 9, "dns_server": ["x"], "reverse": "yes"}))
        settings = load_settings(path)
        assert settings["record_type"] == "A"
        assert settings["dns_server"] == "default"
        assert settings["reverse"] is False

    def test_s4_unknown_allowlist_values_are_dropped(self, tmp_path):
        path = tmp_path / "settings.json"
        path.write_text(json.dumps({"record_type": "EVIL", "dns_server": "6.6.6.6"}))
        settings = load_settings(path)
        assert settings["record_type"] == "A"
        assert settings["dns_server"] == "default"

    def test_s4_round_trip(self, tmp_path):
        path = tmp_path / "settings.json"
        original = {
            "domain": "example.com",
            "record_type": "MX",
            "dns_server": "custom",
            "custom_dns": "1.1.1.1",
            "reverse": False,
            "dnssec": True,
        }
        save_settings(original, path)
        assert load_settings(path) == original

    def test_s4_write_is_atomic(self, tmp_path):
        """A failed write must leave the previous file intact, not a truncated one."""
        path = tmp_path / "settings.json"
        save_settings({**DEFAULT_SETTINGS, "domain": "first.example"}, path)
        with pytest.raises(TypeError):
            save_settings({**DEFAULT_SETTINGS, "domain": object()}, path)
        assert load_settings(path)["domain"] == "first.example"
        assert not [p for p in tmp_path.iterdir() if p.name.startswith(".dig-tui-")]


class TestParsing:
    def test_parses_answer_section(self):
        records = parse_sections(ANSWER_OUTPUT)["ANSWER"]
        assert len(records) == 2
        assert records[0] == {
            "section": "ANSWER",
            "name": "example.com.",
            "ttl": "300",
            "class": "IN",
            "type": "A",
            "data": "93.184.216.34",
        }

    def test_question_section_is_not_collected(self):
        assert "QUESTION" not in parse_sections(ANSWER_OUTPUT)

    def test_parses_all_sections(self):
        sections = parse_sections(MULTI_SECTION_OUTPUT)
        assert set(sections) == {"ANSWER", "AUTHORITY", "ADDITIONAL"}
        assert flatten_sections(sections)[0]["type"] == "A"
        assert [r["section"] for r in flatten_sections(sections)] == [
            "ANSWER",
            "AUTHORITY",
            "ADDITIONAL",
        ]

    def test_nxdomain_has_no_answers(self):
        sections = parse_sections(NXDOMAIN_OUTPUT)
        assert "ANSWER" not in sections
        assert len(sections["AUTHORITY"]) == 1

    def test_empty_output(self):
        assert parse_sections("") == {}
        assert flatten_sections({}) == []

    def test_record_data_with_spaces_is_kept_whole(self):
        spf = '"v=spf1 include:_spf.example.com -all"'
        output = f";; ANSWER SECTION:\nexample.com.\t300\tIN\tTXT\t{spf}\n"
        assert parse_sections(output)["ANSWER"][0]["data"] == spf

    def test_bracketed_txt_record_survives_parsing(self):
        """The S2 payload must round-trip literally; nothing here interprets markup."""
        payload = '"[link=https://phish.example]Verified[/link]"'
        output = f";; ANSWER SECTION:\nevil.com.\t300\tIN\tTXT\t{payload}\n"
        assert parse_sections(output)["ANSWER"][0]["data"] == payload


class TestSummarise:
    def test_summarises_a_successful_query(self):
        assert summarise(ANSWER_OUTPUT) == "NOERROR - 2 answer(s), 24 ms"

    def test_summarises_nxdomain(self):
        assert summarise(NXDOMAIN_OUTPUT) == "NXDOMAIN"

    def test_no_header_yields_empty(self):
        assert summarise("garbage") == ""
