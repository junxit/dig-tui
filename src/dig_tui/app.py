"""Textual application for dig-tui."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    LoadingIndicator,
    RichLog,
    Select,
)
from textual.worker import Worker, WorkerState

from dig_tui.core import (
    DNS_SERVERS,
    EXPORT_FIELDS,
    RECORD_TYPES,
    ValidationError,
    build_dig_command,
    flatten_sections,
    iter_export_rows,
    load_settings,
    parse_sections,
    save_settings,
    summarise,
    validate_dns_server,
    validate_query_name,
    write_csv,
)

#: Hard wall-clock ceiling for a single dig invocation. dig's own +time/+tries bound the
#: network waits; this covers the case where the process hangs for some other reason.
QUERY_TIMEOUT = 15.0


class DigTUI(App):
    """A terminal front end for the ``dig`` DNS lookup utility."""

    CSS = """
    #controls {
        height: auto;
        padding: 1;
        layout: horizontal;
    }
    #domain { width: 1fr; margin-right: 1; }
    #record_type { width: 14; margin-right: 1; }
    #dns_server { width: 28; margin-right: 1; }
    #custom_dns { width: 18; display: none; margin-right: 1; }
    #custom_dns.visible { display: block; }
    #run_btn { margin-top: 1; }
    #toggles { height: auto; padding: 0 1; layout: horizontal; }
    #toggles Checkbox { width: auto; margin-right: 2; }
    #table { display: none; border: round $primary; height: 1fr; margin: 0 1; }
    #table.visible { display: block; }
    #output { border: round $primary; height: 1fr; margin: 0 1; }
    #output.hidden { display: none; }
    #loading { height: 1; display: none; }
    #loading.visible { display: block; }
    """

    # priority=True is required: Input binds `end,ctrl+e` and several other ctrl keys, and a
    # focused widget's bindings otherwise win over the app's. Without it, Ctrl+E never
    # reached save_csv while the domain field had focus - which is the default at startup.
    BINDINGS = [
        Binding("ctrl+j", "save_json", "Save JSON", show=True, priority=True),
        Binding("ctrl+e", "save_csv", "Save CSV", show=True, priority=True),
        Binding("ctrl+t", "save_txt", "Save TXT", show=True, priority=True),
        Binding("ctrl+r", "toggle_view", "Raw/Table", show=True, priority=True),
        Binding("ctrl+q", "quit", "Quit", show=True, priority=True),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.last_output: str = ""
        self.last_records: list[dict[str, str]] = []
        self._show_table = False

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Input(placeholder="Domain (e.g. google.com)", id="domain")
            yield Select(RECORD_TYPES, value="A", id="record_type", allow_blank=False)
            yield Select(DNS_SERVERS, value="default", id="dns_server", allow_blank=False)
            yield Input(placeholder="Custom IP", id="custom_dns")
            yield Button("Dig", id="run_btn", variant="primary")
        with Horizontal(id="toggles"):
            yield Checkbox("Reverse (-x)", id="reverse")
            yield Checkbox("DNSSEC", id="dnssec")
        yield LoadingIndicator(id="loading")
        # markup=False is load-bearing: dig output is attacker-controlled (TXT records in
        # particular), and Rich markup in it would otherwise be parsed. `[link=...]` renders
        # as a clickable hyperlink with attacker-chosen text, and malformed tags raise
        # MarkupError, which would swallow the whole response.
        yield RichLog(id="output", highlight=True, markup=False, wrap=True, max_lines=5000)
        yield DataTable(id="table", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Dig TUI"
        table = self.query_one("#table", DataTable)
        table.add_columns(*(field.title() for field in EXPORT_FIELDS))
        table.cursor_type = "row"

        settings = load_settings()
        self.query_one("#domain", Input).value = settings["domain"]
        self.query_one("#record_type", Select).value = settings["record_type"]
        self.query_one("#dns_server", Select).value = settings["dns_server"]
        self.query_one("#custom_dns", Input).value = settings["custom_dns"]
        self.query_one("#reverse", Checkbox).value = settings["reverse"]
        self.query_one("#dnssec", Checkbox).value = settings["dnssec"]

        if settings["dns_server"] == "custom":
            self.query_one("#custom_dns").add_class("visible")

        self.query_one("#domain", Input).focus()

    # ------------------------------------------------------------------ events

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "dns_server":
            custom_input = self.query_one("#custom_dns")
            if event.value == "custom":
                custom_input.add_class("visible")
                custom_input.focus()
            else:
                custom_input.remove_class("visible")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.run_dig()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run_btn":
            self.run_dig()

    # ------------------------------------------------------------------ query

    def _current_settings(self) -> dict[str, Any]:
        return {
            "domain": self.query_one("#domain", Input).value,
            "record_type": self.query_one("#record_type", Select).value,
            "dns_server": self.query_one("#dns_server", Select).value,
            "custom_dns": self.query_one("#custom_dns", Input).value,
            "reverse": self.query_one("#reverse", Checkbox).value,
            "dnssec": self.query_one("#dnssec", Checkbox).value,
        }

    def run_dig(self) -> None:
        """Validate the current inputs and start a query worker."""
        settings = self._current_settings()
        server: str | None = settings["dns_server"]

        try:
            validate_query_name(settings["domain"])
            if server == "custom":
                server = validate_dns_server(settings["custom_dns"])
            cmd = build_dig_command(
                settings["domain"],
                settings["record_type"],
                server,
                reverse=settings["reverse"],
                dnssec=settings["dnssec"],
            )
        except ValidationError as exc:
            self.notify(str(exc), severity="error", title="Invalid input")
            return

        try:
            save_settings(settings)
        except OSError as exc:
            self.notify(f"Could not save settings: {exc}", severity="warning")

        log = self.query_one("#output", RichLog)
        log.clear()
        log.write(Text(f"> {' '.join(cmd)}", style="bold cyan"))
        self.execute_query(cmd)

    async def _run_dig_process(self, cmd: list[str]) -> str:
        """Run dig off the event loop and return its combined output.

        Args:
            cmd: argv produced by :func:`build_dig_command`.

        Returns:
            stdout concatenated with stderr.

        Raises:
            FileNotFoundError: If the dig binary is missing.
            asyncio.TimeoutError: If the process exceeds :data:`QUERY_TIMEOUT`.
        """
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=QUERY_TIMEOUT)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
        return stdout.decode("utf-8", "replace") + stderr.decode("utf-8", "replace")

    def execute_query(self, cmd: list[str]) -> None:
        """Start the query worker, replacing any query already in flight."""
        self._set_loading(True)
        self.run_worker(
            self._query_worker(cmd),
            name="dig",
            group="dig",
            exclusive=True,
            exit_on_error=False,
        )

    async def _query_worker(self, cmd: list[str]) -> None:
        log = self.query_one("#output", RichLog)
        try:
            output = await self._run_dig_process(cmd)
        except asyncio.CancelledError:
            # A newer query superseded this one; it owns the loading state now.
            raise
        except FileNotFoundError:
            self._fail("Command 'dig' not found. Install it (e.g. `brew install bind`).")
            return
        except asyncio.TimeoutError:
            self._fail(f"Query timed out after {QUERY_TIMEOUT:.0f}s.")
            return
        except OSError as exc:
            self._fail(f"Error running dig: {exc}")
            return

        self._set_loading(False)
        self.last_output = output
        self.last_records = flatten_sections(parse_sections(output))
        log.write(output)
        self._refresh_table()

        status = summarise(output)
        if status:
            self.sub_title = status

    def _fail(self, message: str) -> None:
        """Report a query failure in both the log and a notification."""
        self._set_loading(False)
        self.last_output = message
        self.query_one("#output", RichLog).write(Text(message, style="bold red"))
        self.notify(message, severity="error", title="Query failed")

    def _set_loading(self, active: bool) -> None:
        self.query_one("#loading").set_class(active, "visible")
        self.query_one("#run_btn", Button).disabled = active

    def _refresh_table(self) -> None:
        table = self.query_one("#table", DataTable)
        table.clear()
        for record in self.last_records:
            # Text(...) rather than raw str for the same reason RichLog sets markup=False:
            # DataTable parses markup in string cells, so a TXT record containing `[/bold]`
            # would raise MarkupError and a `[link=...]` would render as a live hyperlink.
            table.add_row(*(Text(record.get(field, "")) for field in EXPORT_FIELDS))

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        """Clear the loading state if a worker dies in a way the worker body did not handle.

        `Worker.StateChanged` is the only worker message Textual emits; without this, an
        unexpected exception would leave the Dig button disabled for the rest of the session.
        """
        if event.worker.group != "dig":
            return
        if event.state is WorkerState.ERROR:
            self._set_loading(False)
            self.notify(f"Query failed: {event.worker.error}", severity="error")
        elif event.state is WorkerState.CANCELLED:
            # Superseded by a newer query, which owns the loading state.
            pass

    # ----------------------------------------------------------------- actions

    def action_toggle_view(self) -> None:
        """Switch between the raw dig output and the parsed record table."""
        self._show_table = not self._show_table
        self.query_one("#table").set_class(self._show_table, "visible")
        self.query_one("#output").set_class(self._show_table, "hidden")

    def _export(
        self, path: Path, writer: Callable[[Path], None], description: str, title: str
    ) -> None:
        """Run an export, reporting failure through a notification instead of raising.

        Args:
            path: Destination file.
            writer: Callable taking the path and performing the write.
            description: Text describing what was saved.
            title: Notification title.
        """
        try:
            writer(path)
        except OSError as exc:
            self.notify(
                f"Could not write {path.name}: {exc}", severity="error", title="Export failed"
            )
            return
        self.notify(f"Saved {description} to {path.absolute()}", title=title)

    def action_save_txt(self) -> None:
        if not self.last_output:
            self.notify("No output to save", severity="warning")
            return
        self._export(
            Path("dig_output.txt"),
            lambda p: p.write_text(self.last_output, encoding="utf-8"),
            "raw output",
            "Saved TXT",
        )

    def action_save_json(self) -> None:
        if not self.last_records:
            self.notify(
                "No parsed records to save (run a query that returns records)", severity="warning"
            )
            return
        rows = iter_export_rows(self.last_records)
        self._export(
            Path("dig_output.json"),
            lambda p: p.write_text(json.dumps(rows, indent=2), encoding="utf-8"),
            f"{len(rows)} record(s)",
            "Saved JSON",
        )

    def action_save_csv(self) -> None:
        if not self.last_records:
            self.notify(
                "No parsed records to save (run a query that returns records)", severity="warning"
            )
            return
        rows = iter_export_rows(self.last_records)
        self._export(
            Path("dig_output.csv"),
            lambda p: write_csv(p, rows),
            f"{len(rows)} record(s)",
            "Saved CSV",
        )


def main() -> None:
    """Console entry point."""
    DigTUI().run()


if __name__ == "__main__":
    main()
