"""Integration tests driving the Textual app through its test harness.

These cover the wiring that unit tests over ``core`` cannot reach: that the app mounts, that
validation actually blocks a query from being spawned, and that untrusted dig output reaches
the screen without being interpreted.
"""

from __future__ import annotations

import pytest
from rich.text import Text
from textual.widgets import Button, Checkbox, DataTable, Input, RichLog, Select

from dig_tui.app import DigTUI
from dig_tui.core import DEFAULT_SETTINGS, EXPORT_FIELDS

ANSWER_OUTPUT = (
    ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
    ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0\n"
    "\n"
    ";; ANSWER SECTION:\n"
    "example.com.\t300\tIN\tA\t93.184.216.34\n"
    "\n"
    ";; Query time: 12 msec\n"
)

#: A TXT record that would render as a clickable hyperlink if markup were parsed.
MARKUP_PAYLOAD = (
    ";; ANSWER SECTION:\n"
    'evil.com.\t300\tIN\tTXT\t"[link=https://phish.example]Verified by Cloudflare[/link]"\n'
)

#: Malformed markup; this raised MarkupError and swallowed the whole response before the fix.
BROKEN_MARKUP_PAYLOAD = ';; ANSWER SECTION:\nevil.com.\t300\tIN\tTXT\t"[/bold]"\n'


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """Keep tests away from the real ~/.dig-tui-settings.json."""
    path = tmp_path / "settings.json"
    monkeypatch.setattr("dig_tui.app.load_settings", lambda: dict(DEFAULT_SETTINGS))
    monkeypatch.setattr("dig_tui.app.save_settings", lambda settings: None)
    return path


def stub_dig(app: DigTUI, output: str) -> list:
    """Replace the subprocess call with a canned response, recording the argv used."""
    calls: list = []

    async def _fake(cmd):
        calls.append(cmd)
        return output

    app._run_dig_process = _fake
    return calls


class TestMount:
    async def test_app_mounts(self):
        app = DigTUI()
        async with app.run_test():
            assert app.query_one("#domain", Input) is not None
            assert app.query_one("#record_type", Select).value == "A"
            assert app.query_one("#dns_server", Select).value == "default"
            assert len(app.query_one("#table", DataTable).columns) == 6

    async def test_custom_dns_field_toggles_with_selection(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            custom = app.query_one("#custom_dns")
            assert not custom.has_class("visible")
            app.query_one("#dns_server", Select).value = "custom"
            await pilot.pause()
            assert custom.has_class("visible")
            app.query_one("#dns_server", Select).value = "1.1.1.1"
            await pilot.pause()
            assert not custom.has_class("visible")


class TestS1QueryIsBlockedBeforeSpawn:
    """Validation must stop a hostile value before any process is created."""

    @pytest.mark.parametrize("hostile", ["-f/etc/passwd", "@8.8.8.8", "bad domain.com", ""])
    async def test_s1_no_process_spawned_for_hostile_input(self, hostile):
        app = DigTUI()
        async with app.run_test() as pilot:
            calls = stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = hostile
            await pilot.click("#run_btn")
            await pilot.pause()
            assert calls == [], f"dig was invoked with hostile input {hostile!r}"
            assert len(app._notifications) == 1

    async def test_s1_valid_input_uses_flag_form(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            calls = stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            assert len(calls) == 1
            cmd = calls[0]
            assert cmd[cmd.index("-q") + 1] == "example.com"

    async def test_s1_custom_server_must_be_an_ip(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            calls = stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "example.com"
            app.query_one("#dns_server", Select).value = "custom"
            app.query_one("#custom_dns", Input).value = "dns.google"
            await pilot.click("#run_btn")
            await pilot.pause()
            assert calls == []


class TestS2MarkupIsNotInterpreted:
    async def test_s2_richlog_has_markup_disabled(self):
        app = DigTUI()
        async with app.run_test():
            assert app.query_one("#output", RichLog).markup is False

    async def test_s2_link_payload_renders_literally(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, MARKUP_PAYLOAD)
            app.query_one("#domain", Input).value = "evil.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            rendered = "\n".join(strip.text for strip in app.query_one("#output", RichLog).lines)
            assert "[link=https://phish.example]" in rendered
            assert "[/link]" in rendered

    async def test_s2_broken_markup_does_not_suppress_output(self):
        """Before the fix, MarkupError was swallowed and the response vanished."""
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, BROKEN_MARKUP_PAYLOAD)
            app.query_one("#domain", Input).value = "evil.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            rendered = "\n".join(strip.text for strip in app.query_one("#output", RichLog).lines)
            assert "[/bold]" in rendered
            assert app.last_records, "records were parsed despite the malformed markup"

    @pytest.mark.parametrize("payload", [MARKUP_PAYLOAD, BROKEN_MARKUP_PAYLOAD])
    async def test_s2_table_cells_do_not_parse_markup(self, payload):
        """DataTable parses markup in str cells, so cells must be Text objects.

        This regressed once already: adding the table re-opened S2 on a second path.
        """
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, payload)
            app.query_one("#domain", Input).value = "evil.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            await pilot.press("ctrl+r")
            await pilot.pause()

            table = app.query_one("#table", DataTable)
            assert table.row_count == 1
            data_cell = table.get_row_at(0)[EXPORT_FIELDS.index("data")]
            assert isinstance(data_cell, Text), "cell must be Text, not a markup-parsed str"
            assert "[" in data_cell.plain, "markup was stripped instead of shown literally"
            assert not data_cell.spans, "markup was interpreted into style spans"


class TestQueryFlow:
    async def test_results_populate_log_and_table(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            assert len(app.last_records) == 1
            assert app.query_one("#table", DataTable).row_count == 1
            assert app.sub_title == "NOERROR - 1 answer(s), 12 ms"

    async def test_missing_dig_binary_is_reported(self):
        app = DigTUI()
        async with app.run_test() as pilot:

            async def _missing(cmd):
                raise FileNotFoundError(2, "No such file or directory", "dig")

            app._run_dig_process = _missing
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            assert "not found" in app.last_output
            assert app.query_one("#run_btn", Button).disabled is False

    async def test_timeout_is_reported_and_ui_recovers(self):
        import asyncio

        app = DigTUI()
        async with app.run_test() as pilot:

            async def _timeout(cmd):
                raise asyncio.TimeoutError

            app._run_dig_process = _timeout
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            assert "timed out" in app.last_output
            assert app.query_one("#run_btn", Button).disabled is False
            assert not app.query_one("#loading").has_class("visible")

    async def test_unexpected_error_does_not_wedge_the_ui(self):
        """An exception the worker body does not handle must still re-enable the button."""
        app = DigTUI()
        async with app.run_test() as pilot:

            async def _boom(cmd):
                raise RuntimeError("unexpected")

            app._run_dig_process = _boom
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            await pilot.pause()
            assert app.query_one("#run_btn", Button).disabled is False
            assert not app.query_one("#loading").has_class("visible")
            assert any("unexpected" in n.message for n in app._notifications)

    async def test_reverse_lookup_toggle_builds_x_command(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            calls = stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "8.8.8.8"
            app.query_one("#reverse", Checkbox).value = True
            await pilot.click("#run_btn")
            await pilot.pause()
            assert "-x" in calls[0]

    async def test_toggle_view_switches_panes(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            await pilot.press("ctrl+r")
            assert app.query_one("#table").has_class("visible")
            assert app.query_one("#output").has_class("hidden")
            await pilot.press("ctrl+r")
            assert not app.query_one("#table").has_class("visible")


class TestExports:
    async def test_export_without_results_warns(self):
        app = DigTUI()
        async with app.run_test() as pilot:
            await pilot.press("ctrl+j")
            await pilot.pause()
            assert len(app._notifications) == 1
            assert not app.last_records

    async def test_exports_write_files(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()
            for key, filename in [
                ("ctrl+t", "dig_output.txt"),
                ("ctrl+j", "dig_output.json"),
                ("ctrl+e", "dig_output.csv"),
            ]:
                await pilot.press(key)
                await pilot.pause()
                assert (tmp_path / filename).exists(), f"{filename} not written"

    async def test_export_failure_is_notified_not_raised(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        app = DigTUI()
        async with app.run_test() as pilot:
            stub_dig(app, ANSWER_OUTPUT)
            app.query_one("#domain", Input).value = "example.com"
            await pilot.click("#run_btn")
            await pilot.pause()

            def _deny(*args, **kwargs):
                raise PermissionError(13, "Permission denied")

            monkeypatch.setattr("pathlib.Path.write_text", _deny)
            await pilot.press("ctrl+t")
            await pilot.pause()
            assert app.is_running, "app survived an unwritable output directory"
            assert any("Permission denied" in n.message for n in app._notifications)
