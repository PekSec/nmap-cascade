#!/usr/bin/env python3
"""Offline integration checks: the real wrapper/report parser, a fake Nmap."""
import json
from html.parser import HTMLParser
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import cascade_report
FAKE_NMAP = r'''#!/usr/bin/env python3
import json, os, signal, sys, time
from pathlib import Path
a = sys.argv[1:]
if a == ["--version"]:
    print("Nmap version 7.95 (fixture)")
    sys.exit(0)
if "--script-help" in a:
    Path(a[a.index("-oX")+1]).write_text("<nse-scripts><script filename='http-git.nse'><description>Fixture</description></script></nse-scripts>")
    sys.exit(0)
with open(os.environ["CALLS"], "a") as f:
    f.write(json.dumps(a) + "\n")
discovery = "-p-" in a
case = os.environ.get("CASE", "normal")
if case == "interrupt" and not discovery:
    Path(os.environ["READY"]).write_text(str(os.getpid()))
    time.sleep(30)
if case == "failure" and not discovery:
    print("fixture failure", file=sys.stderr)
    sys.exit(7)
def host(ip, port, state="open"):
    scripts = "" if discovery else """<script id="http-git" output="Potential repository">
      <table key="evidence"><elem key="state">LIKELY VULNERABLE</elem></table></script>
      <script id="fixture-error" output="ERROR: timed out"/>"""
    return f"""<host><status state="up" reason="{'user-set' if discovery else 'syn-ack'}"/>
    <address addr="{ip}" addrtype="ipv4"/><ports>
    <extraports state="closed" count="65534"><extrareasons reason="resets" count="65534"/></extraports>
    <port protocol="tcp" portid="{port}"><state state="{state}" reason="syn-ack"/>
    <service name="http" method="probed" conf="10" product="Fixture"/>{scripts}</port>
    </ports><os><osmatch name="Fixture OS" accuracy="95"/></os>
    <trace><hop ttl="1" ipaddr="192.0.2.254"/></trace></host>"""
if discovery:
    body = host("192.0.2.1", 443 if case == "shared" else 22, "closed" if case == "empty" else "open")
    if case != "empty":
        body += host("192.0.2.2", 443)
    if case == "compressed":
        # -vv aggregates sufficiently large groups of identical port states.
        additional = ''.join(f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/></port>' for p in range(80, 155))
        body = body.replace('</ports>', additional + '</ports>')
    if case == "mixed":
        body = body.replace('</ports>', '<port protocol="udp" portid="53"><state state="open"/></port><port protocol="tcp" portid="8080"><state state="open|filtered"/></port></ports>')
else:
    ip = a[-1]
    body = host(ip, int(a[a.index("-p")+1].split(",")[0]),
                "closed" if ip.endswith(".1") else "open")
    if case == "compressed":
        body = f'<host><status state="up" reason="syn-ack"/><address addr="{ip}" addrtype="ipv4"/><ports><extraports state="closed" count="76"><extrareasons reason="resets" count="76"/></extraports></ports></host>'
xml = '<nmaprun start="1">' + body + '<runstats><finished time="2" exit="success"/></runstats></nmaprun>'
if case == "failed-xml" and not discovery:
    xml = xml.replace('exit="success"', 'exit="error" errormsg="fixture failure"')
if case == "html" and not discovery:
    xml = xml.replace('Potential repository', '&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt; &amp; evidence')
    xml = xml.replace('product="Fixture"/>', 'product="Fixture"><cpe/><cpe>cpe:/a:fixture</cpe></service>')
if case == "malformed" and discovery:
    xml = "<nmaprun><host>"
if case == "missing" and discovery:
    sys.exit(0)
for flag, content in (("-oX", xml), ("-oN", "No machine parsing of text\n"), ("-oG", "Not parsed\n")):
    Path(a[a.index(flag)+1]).write_text(content)
if case == "failed-xml" and not discovery:
    sys.exit(7)
'''


class CascadeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cascade-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        binary = self.work / "nmap"
        binary.write_text(FAKE_NMAP)
        binary.chmod(0o755)
        self.env = {**os.environ, "PATH": f"{self.work}:{os.environ['PATH']}",
                    "CALLS": str(self.work / "calls.jsonl"),
                    "READY": str(self.work / "ready")}
        self.env.pop("MIN_RATE", None)
        self.env.pop("MAX_RETRIES", None)

    def run_scan(self, case="normal", target="192.0.2.0/30", timing="T3"):
        self.env["CASE"] = case
        result = subprocess.run(["bash", str(ROOT / "nmap-cascade.sh")],
                                input=f"test\n{timing}\n{target}\n", text=True,
                                cwd=self.work, env=self.env, capture_output=True, timeout=15)
        return result

    def calls(self):
        path = self.work / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def report(self):
        paths = list(self.work.glob("nmap_*/RESULTS.json"))
        self.assertEqual(len(paths), 1, "one structured report must be produced")
        self.assertTrue((paths[0].parent / "REPORT.html").is_file(), "HTML must accompany completed and partial reports")
        return json.loads(paths[0].read_text()), paths[0].parent

    def test_html_report_is_standalone_and_escapes_evidence(self):
        result = self.run_scan("html")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, directory = self.report()
        document = (directory / "REPORT.html").read_text()
        tags, text = [], []
        parser = HTMLParser()
        parser.handle_starttag = lambda tag, attrs: tags.append((tag, dict(attrs)))
        parser.handle_data = text.append
        parser.feed(document)
        self.assertIn('</pre><script>alert(1)</script><img src=x onerror=alert(2)> & evidence', ''.join(text))
        self.assertFalse(any(tag in ("script", "img", "iframe", "object", "link") for tag, _ in tags))
        self.assertFalse(any(key.startswith("on") for _, attrs in tags for key in attrs))
        self.assertTrue(any(tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy" for tag, attrs in tags))
        for evidence in ("192.0.2.1", "192.0.2.2", "http-git", "LIKELY VULNERABLE", "ERROR: timed out", "95", "cpe:/a:fixture"):
            self.assertIn(evidence, ''.join(text))
        for _, attrs in tags:
            if "href" in attrs:
                self.assertTrue(attrs["href"].startswith(("#", "./")), attrs["href"])
        self.assertIn("REPORT.html", result.stderr)

    def test_host_scoped_enrichment_and_evidence(self):
        result = self.run_scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 3)  # one discovery, one enrichment per host
        self.assertEqual([(a[-1], a[a.index("-p")+1]) for a in calls[1:]],
                         [("192.0.2.1", "22"), ("192.0.2.2", "443")])
        self.assertEqual(calls[0][calls[0].index("--min-rate")+1], "750")
        self.assertEqual(calls[0][calls[0].index("--max-retries")+1], "2")
        for flag in ("-O", "--osscan-limit", "--traceroute", "-sV", "-sC", "--script", "--version-all"):
            self.assertNotIn(flag, calls[0])
        self.assertNotIn("--open", calls[0])
        for call in calls[1:]:
            self.assertIn("--version-all", call)
            self.assertIn("--script", call)
            self.assertNotIn("-sC", call)
            self.assertNotIn("--min-rate", call)
            self.assertNotIn("--max-retries", call)
            self.assertEqual("-O" in call, os.geteuid() == 0)
            if os.geteuid() == 0:
                self.assertEqual(call[call.index("--max-os-tries")+1], "1")
        self.assertEqual("--traceroute" in calls[1], os.geteuid() == 0)
        report, directory = self.report()
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["min_rate"], "750")
        self.assertEqual(report["max_retries"], "2")
        self.assertEqual(report["counts"]["discovered_open_endpoints"], 2)
        self.assertEqual(report["counts"]["latest_observed_open_endpoints"], 1)
        self.assertEqual(report["hosts"][0]["state_changes"][0]["to"], "closed")
        summary = (directory / "SUMMARY.txt").read_text()
        for evidence in ("192.0.2.1", "192.0.2.2", "http-git", "ERROR: timed out", "95"):
            self.assertIn(evidence, summary)
        self.assertIn("LIKELY VULNERABLE", json.dumps(report))
        self.assertTrue((directory / "script-selection.xml").exists())

    def test_empty_is_success_without_enrichment(self):
        result = self.run_scan("empty")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 1)
        report, _ = self.report()
        self.assertEqual(report["counts"]["discovered_open_endpoints"], 0)
        self.assertEqual(report["status"], "completed")

    def test_bad_xml_is_not_an_empty_success(self):
        for case in ("malformed", "missing"):
            with self.subTest(case=case):
                result = self.run_scan(case)
                self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls()), 2)
        for path in self.work.glob("nmap_*/RESULTS.json"):
            self.assertEqual(json.loads(path.read_text())["status"], "partial")
        self.assertEqual(len(list(self.work.glob("nmap_*/RESULTS.json"))), 2)

    def test_failure_preserves_discovery_and_exit_code(self):
        result = self.run_scan("failure")
        self.assertEqual(result.returncode, 7, result.stderr)
        report, directory = self.report()
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["counts"]["discovered_open_endpoints"], 2)
        self.assertIn("failed", [p["status"] for p in report["phases"]])
        self.assertTrue(any("fixture failure" in p.read_text()
                            for p in directory.glob("*.stderr.log")))

    def test_default_timing_hostname_and_overrides(self):
        self.env.update(MIN_RATE="123.5", MAX_RETRIES="4")
        result = self.run_scan(target="example.test", timing="")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertIn("-T3", calls[0])
        self.assertEqual(calls[0][calls[0].index("--min-rate")+1], "123.5")
        self.assertEqual(calls[0][calls[0].index("--max-retries")+1], "4")
        report, _ = self.report()
        self.assertEqual(report["min_rate"], "123.5")
        self.assertEqual(report["max_retries"], "4")
        for call in calls[1:]:
            self.assertIn("http.host=example.test,tls.servername=example.test", call)
            self.assertTrue(call[-1].startswith("192.0.2."))

    def test_invalid_target_rejected_before_scanning(self):
        for target in ("::1", "--script=all", "192.0.2.0/33", "a,b", "host name"):
            with self.subTest(target=target):
                self.assertNotEqual(self.run_scan(target=target).returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_unique_directories(self):
        self.assertEqual(self.run_scan("empty").returncode, 0)
        self.assertEqual(self.run_scan("empty").returncode, 0)
        self.assertEqual(len(list(self.work.glob("nmap_*/SUMMARY.txt"))), 2)

    def test_aggregated_enrichment_states_replace_discovery(self):
        result = self.run_scan("compressed")
        self.assertEqual(result.returncode, 0, result.stderr)
        report, _ = self.report()
        self.assertEqual(report["counts"]["latest_observed_open_endpoints"], 0)
        self.assertEqual([h["state_changes"][0]["to"] for h in report["hosts"]], ["closed", "closed"])

    def test_invalid_rate_controls_rejected_before_scanning(self):
        for name, value in (("MIN_RATE", "nan"), ("MIN_RATE", "0"),
                            ("MIN_RATE", ""), ("MAX_RETRIES", "-1")):
            with self.subTest(name=name, value=value):
                self.env[name] = value
                self.assertNotEqual(self.run_scan().returncode, 0)
                self.env.pop(name)
        self.assertEqual(self.calls(), [])

    def test_empty_scan_name_is_rejected(self):
        result = subprocess.run(["bash", str(ROOT / "nmap-cascade.sh")],
                                input="\nT3\n192.0.2.1\n", text=True,
                                cwd=self.work, env=self.env, capture_output=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_shared_port_counts_endpoints_not_port_numbers(self):
        result = self.run_scan("shared")
        self.assertEqual(result.returncode, 0, result.stderr)
        report, _ = self.report()
        self.assertEqual(report["counts"]["discovered_open_endpoints"], 2)
        self.assertEqual(report["counts"]["discovered_unique_tcp_ports"], 1)

    def test_only_open_tcp_is_scheduled(self):
        result = self.run_scan("mixed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([a[a.index("-p")+1] for a in self.calls()[1:]], ["22", "443"])

    def test_explicit_aggregate_ports_and_ambiguous_states(self):
        host = {"ports": [], "extraports": [
            {"state": "closed", "count": "2", "reasons": [{"proto": "tcp", "ports": "22,80-80", "reason": "resets"}]},
            {"state": "filtered", "count": "1", "reasons": []}]}
        cascade_report.reconcile_aggregates(host, {22, 80, 443})
        self.assertEqual([(p["port"], p["state"]["state"]) for p in host["ports"]],
                         [(22, "closed"), (80, "closed"), (443, "unknown")])

    def test_failed_xml_keeps_untrusted_observations(self):
        result = self.run_scan("failed-xml")
        self.assertEqual(result.returncode, 7, result.stderr)
        report, _ = self.report()
        self.assertEqual(report["status"], "partial")
        observations = report["hosts"][0]["observations"]
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[1]["process_status"], "failed")
        self.assertEqual(observations[1]["nmap_finished"]["exit"], "error")
        self.assertEqual(report["counts"]["latest_observed_open_endpoints"], 2)

    def test_log_failure_does_not_report_success(self):
        tee = self.work / "tee"
        tee.write_text('#!/usr/bin/env python3\nimport sys\nsys.stdout.write(sys.stdin.read())\nsys.exit(1)\n')
        tee.chmod(0o755)
        result = self.run_scan("empty")
        self.assertNotEqual(result.returncode, 0)
        report, _ = self.report()
        self.assertEqual(report["status"], "partial")

    def test_interrupt_stops_child_and_writes_partial_report(self):
        self.env["CASE"] = "interrupt"
        process = subprocess.Popen(["bash", str(ROOT / "nmap-cascade.sh")],
                                   cwd=self.work, env=self.env, stdin=subprocess.PIPE,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
        self.addCleanup(lambda: process.poll() is None and process.kill())
        process.stdin.write("test\nT3\n192.0.2.0/30\n")
        process.stdin.close()
        deadline = time.monotonic() + 8
        ready = self.work / "ready"
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(ready.exists(), "enrichment must start")
        child_pid = int(ready.read_text())
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=5), 143)
        with self.assertRaises(ProcessLookupError):
            os.kill(child_pid, 0)
        report, _ = self.report()
        self.assertEqual(report["status"], "partial")
        self.assertIn("interrupted", [p["status"] for p in report["phases"]])


if __name__ == "__main__":
    unittest.main()
