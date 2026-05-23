import json
import csv
import subprocess
import re
from pathlib import Path
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Select, Button, RichLog
from textual.containers import Horizontal
from textual.binding import Binding

SETTINGS_FILE = Path.home() / ".dig-tui-settings.json"

RECORD_TYPES = [
    ("A", "A"), ("AAAA", "AAAA"), ("CNAME", "CNAME"),
    ("MX", "MX"), ("NS", "NS"), ("PTR", "PTR"),
    ("SOA", "SOA"), ("SRV", "SRV"), ("TXT", "TXT"),
    ("ANY", "ANY")
]

DNS_SERVERS = [
    ("System Default", "default"),
    ("Cloudflare (1.1.1.1)", "1.1.1.1"),
    ("Google (8.8.8.8)", "8.8.8.8"),
    ("Quad9 (9.9.9.9)", "9.9.9.9"),
    ("OpenDNS (208.67.222.222)", "208.67.222.222"),
    ("Custom", "custom")
]

class DigTUI(App):
    CSS = """
    #controls {
        height: auto;
        padding: 1;
        layout: horizontal;
    }
    #domain { width: 1fr; margin-right: 1; }
    #record_type { width: 15; margin-right: 1; }
    #dns_server { width: 30; margin-right: 1; }
    #custom_dns { width: 20; display: none; margin-right: 1; }
    #custom_dns.visible { display: block; }
    #run_btn { margin-top: 1; }
    #output { border: round $primary; height: 1fr; margin: 0 1; }
    """

    BINDINGS = [
        Binding("ctrl+j", "save_json", "Save JSON", show=True),
        Binding("ctrl+e", "save_csv", "Save CSV", show=True),
        Binding("ctrl+t", "save_txt", "Save TXT", show=True),
        Binding("ctrl+q", "quit", "Quit", show=True)
    ]

    def __init__(self):
        super().__init__()
        self.last_output = ""
        self.last_parsed = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="controls"):
            yield Input(placeholder="Domain (e.g. google.com)", id="domain")
            yield Select(RECORD_TYPES, value="A", id="record_type")
            yield Select(DNS_SERVERS, value="default", id="dns_server")
            yield Input(placeholder="Custom IP", id="custom_dns")
            yield Button("Dig", id="run_btn", variant="primary")
        yield RichLog(id="output", highlight=True, markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.title = "Dig TUI"
        settings = self.load_settings()
        if settings:
            self.query_one("#domain").value = settings.get("domain", "")
            
            # Textual Select requires value to match options
            try:
                self.query_one("#record_type").value = settings.get("record_type", "A")
            except:
                self.query_one("#record_type").value = "A"
                
            server = settings.get("dns_server", "default")
            try:
                self.query_one("#dns_server").value = server
            except:
                self.query_one("#dns_server").value = "default"
            
            custom_dns = settings.get("custom_dns", "")
            self.query_one("#custom_dns").value = custom_dns
            
            if server == "custom":
                self.query_one("#custom_dns").add_class("visible")
        
        self.query_one("#domain").focus()

    def load_settings(self):
        if SETTINGS_FILE.exists():
            try:
                return json.loads(SETTINGS_FILE.read_text())
            except Exception:
                pass
        return {}

    def save_settings(self):
        settings = {
            "domain": self.query_one("#domain").value,
            "record_type": self.query_one("#record_type").value,
            "dns_server": self.query_one("#dns_server").value,
            "custom_dns": self.query_one("#custom_dns").value,
        }
        SETTINGS_FILE.write_text(json.dumps(settings))

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

    def run_dig(self) -> None:
        self.save_settings()
        domain = self.query_one("#domain").value.strip()
        if not domain:
            self.notify("Please enter a domain", severity="error")
            return

        record_type = self.query_one("#record_type").value
        server = self.query_one("#dns_server").value
        
        cmd = ["dig"]
        if server == "custom":
            custom_server = self.query_one("#custom_dns").value.strip()
            if custom_server:
                cmd.append(f"@{custom_server}")
        elif server != "default":
            cmd.append(f"@{server}")

        cmd.append(domain)
        cmd.append(record_type)

        log = self.query_one("#output")
        log.clear()
        cmd_str = " ".join(cmd)
        log.write(f"[bold cyan]> {cmd_str}[/bold cyan]")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            self.last_output = result.stdout + result.stderr
            self.parse_output(self.last_output)
            log.write(self.last_output)
        except FileNotFoundError:
            self.last_output = "Command 'dig' not found. Please ensure it is installed on your system."
            log.write(f"[bold red]{self.last_output}[/bold red]")
        except Exception as e:
            self.last_output = str(e)
            log.write(f"[bold red]Error running dig:[/bold red] {e}")

    def parse_output(self, output: str):
        self.last_parsed = []
        in_answer = False
        for line in output.splitlines():
            if line.startswith(";; ANSWER SECTION:"):
                in_answer = True
                continue
            if in_answer:
                if not line.strip() or line.startswith(";;"):
                    in_answer = False
                    continue
                parts = re.split(r'\s+', line.strip(), maxsplit=4)
                if len(parts) >= 5:
                    self.last_parsed.append({
                        "name": parts[0],
                        "ttl": parts[1],
                        "class": parts[2],
                        "type": parts[3],
                        "data": parts[4]
                    })

    def action_save_txt(self):
        if not self.last_output:
            self.notify("No output to save", severity="warning")
            return
        path = Path("dig_output.txt")
        path.write_text(self.last_output)
        self.notify(f"Saved raw output to {path.absolute()}", title="Saved TXT")

    def action_save_json(self):
        if not self.last_parsed:
            self.notify("No parsed answers to save (try a query first, or make sure the query returns answers)", severity="warning")
            return
        path = Path("dig_output.json")
        path.write_text(json.dumps(self.last_parsed, indent=2))
        self.notify(f"Saved parsed answers to {path.absolute()}", title="Saved JSON")

    def action_save_csv(self):
        if not self.last_parsed:
            self.notify("No parsed answers to save (try a query first, or make sure the query returns answers)", severity="warning")
            return
        path = Path("dig_output.csv")
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["name", "ttl", "class", "type", "data"])
            writer.writeheader()
            writer.writerows(self.last_parsed)
        self.notify(f"Saved parsed answers to {path.absolute()}", title="Saved CSV")

if __name__ == "__main__":
    app = DigTUI()
    app.run()
