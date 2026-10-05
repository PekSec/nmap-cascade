#!/usr/bin/env python3
"""Structured handoff and evidence reporting for nmap-cascade (stdlib only)."""
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import sys
from datetime import datetime, timezone
import xml.etree.ElementTree as ET
from report_html import render_report


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def target_hostname(target):
    if ":" in target:
        raise ValueError("IPv6 is outside this scanner's IPv4/TCP scope.")
    if "/" in target:
        ipaddress.IPv4Network(target, strict=False)
        return ""
    try:
        ipaddress.IPv4Address(target)
        return ""
    except ValueError:
        if re.fullmatch(r"[0-9.]+", target):
            raise ValueError("Invalid IPv4 address.")
    name = target.rstrip(".")
    if len(name) > 253 or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                                   for label in name.split(".")):
        raise ValueError("Use one IPv4 address, IPv4 CIDR, or DNS hostname (no options or ranges).")
    return name


def scripts(parent):
    results = []
    for node in parent.findall("script"):
        output = node.get("output", "")
        script_id = node.get("id", "")
        interpretation = "version_association" if script_id == "vulners" else "script_report"
        if output.upper().startswith("ERROR:"):
            interpretation = "error"
        results.append({"id": script_id, "output": output, "interpretation": interpretation,
                        "reported_states": [e.text for e in node.findall(".//elem[@key='state']")],
                        "xml": ET.tostring(node, encoding="unicode")})
    return results


def read_scan(path, allow_failed=False):
    root = ET.parse(path).getroot()
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or (not allow_failed and finished.get("exit") != "success"):
        raise ValueError("XML does not describe a successfully finished Nmap scan.")
    hosts = []
    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            raise ValueError("Host is missing its IPv4 address.")
        ip = str(ipaddress.IPv4Address(address.get("addr", "")))
        status = host.find("status")
        ports = []
        for port in host.findall("ports/port"):
            number = int(port.get("portid", "0"))
            if not 1 <= number <= 65535:
                raise ValueError("Invalid port number in XML.")
            state = port.find("state")
            if state is None:
                raise ValueError("Port is missing its state.")
            service = port.find("service")
            ports.append({"protocol": port.get("protocol"), "port": number,
                          "state": dict(state.attrib),
                          "service": dict(service.attrib) if service is not None else {},
                          "cpes": [e.text for e in port.findall("service/cpe")],
                          "scripts": scripts(port)})
        hostscript = host.find("hostscript")
        os_node = host.find("os")
        hosts.append({"address": ip, "status": dict(status.attrib) if status is not None else {},
                      "hostnames": [dict(e.attrib) for e in host.findall("hostnames/hostname")],
                      "ports": ports, "scripts": scripts(hostscript) if hostscript is not None else [],
                      "extraports": [{**e.attrib, "reasons": [dict(r.attrib) for r in e.findall("extrareasons")],
                                      "xml": ET.tostring(e, encoding="unicode")}
                                     for e in host.findall("ports/extraports")],
                      "os_matches": [dict(e.attrib) for e in host.findall("os/osmatch")],
                      "os_xml": ET.tostring(os_node, encoding="unicode") if os_node is not None else None,
                      "trace": [dict(e.attrib) for e in host.findall("trace/hop")]})
    if not hosts:
        raise ValueError("No host records: target resolution/coverage could not be established.")
    return {"started": root.get("start"), "finished": finished.get("time"),
            "nmap_finished": dict(finished.attrib), "hosts": hosts}


def selected_scripts(path):
    root = ET.parse(path).getroot()
    names = sorted({node.get("filename") for node in root.findall("script") if node.get("filename")})
    if root.tag != "nse-scripts" or not names:
        raise ValueError("Nmap did not return a nonempty script selection.")
    return names


def open_tcp(host):
    return sorted({p["port"] for p in host["ports"]
                   if p["protocol"] == "tcp" and p["state"].get("state") == "open"})


def reconcile_aggregates(host, requested):
    """Attribute aggregates only with explicit port IDs or a single exact-count state."""
    missing = set(requested) - {p["port"] for p in host["ports"] if p["protocol"] == "tcp"}
    states = {}
    for group in host["extraports"]:
        for reason in group["reasons"]:
            if reason.get("proto") != "tcp" or not reason.get("ports"):
                continue
            for entry in reason["ports"].split(","):
                bounds = entry.split("-")
                first, last = int(bounds[0]), int(bounds[-1])
                if len(bounds) > 2 or not 1 <= first <= last <= 65535:
                    raise ValueError("Invalid aggregate port range.")
                for port in missing.intersection(range(first, last + 1)):
                    states[port] = {"state": group["state"], "reason": reason.get("reason"), "source": "extraports"}
    groups = host["extraports"]
    if len(groups) == 1 and int(groups[0]["count"]) == len(missing):
        for port in missing:
            states.setdefault(port, {"state": groups[0]["state"], "source": "extraports"})
    for port in sorted(missing):
        host["ports"].append({"protocol": "tcp", "port": port,
                              "state": states.get(port, {"state": "unknown", "reason": "not individually attributable"}),
                              "service": {}, "cpes": [], "scripts": []})


def report(directory, exit_code):
    meta = json.loads((directory / "run.json").read_text())
    phases = {}
    errors = []
    events = directory / "events.jsonl"
    if events.exists():
        for line in events.read_text().splitlines():
            try:
                event = json.loads(line)
                phase = phases.setdefault(event["phase"], {})
                phase.update(event)
            except (ValueError, KeyError) as error:
                errors.append(f"Invalid event record: {error}")
    for name in ("script-selection", "discovery"):
        phases.setdefault(name, {"phase": name, "status": "not_started"})
    selected = []
    try:
        selected = selected_scripts(directory / "script-selection.xml")
    except (OSError, ValueError, ET.ParseError) as error:
        errors.append(f"Script selection unavailable: {error}")
    hosts = {}
    discovered = set()
    latest = {}
    for name, phase in list(phases.items()):
        if not phase.get("xml") or name == "script-selection":
            continue
        try:
            scan = read_scan(directory / phase["xml"], allow_failed=True)
        except (OSError, ValueError, ET.ParseError) as error:
            phase["parse_error"] = str(error)
            errors.append(f"{name}: {error}")
            continue
        for observation in scan["hosts"]:
            address = observation["address"]
            host = hosts.setdefault(address, {"address": address, "observations": [], "state_changes": []})
            if name.startswith("enrichment:"):
                reconcile_aggregates(observation, {key[2] for key in discovered if key[0] == address})
            observation.update(phase=name, started=scan["started"], finished=scan["finished"],
                               nmap_finished=scan["nmap_finished"], artifact=phase["xml"], process_status=phase["status"])
            host["observations"].append(observation)
            # Preserve failed-call evidence, but never promote it to a completed observation.
            if phase["status"] != "completed" or scan["nmap_finished"].get("exit") != "success":
                continue
            for port in observation["ports"]:
                key = (address, port["protocol"], port["port"])
                state = port["state"].get("state")
                if name == "discovery" and port["protocol"] == "tcp" and state == "open":
                    discovered.add(key)
                if key in latest and latest[key] != state and state != "unknown":
                    host["state_changes"].append({"protocol": key[1], "port": key[2],
                                                  "from": latest[key], "to": state, "phase": name})
                latest[key] = state
    for address in sorted({key[0] for key in discovered}):
        name = f"enrichment:{address}"
        phases.setdefault(name, {"phase": name, "status": "not_started"})
    limits = ["IPv4 TCP ports 1-65535 only; UDP and IPv6 were not scanned.",
              "-Pn assumes hosts are up; user-set status alone is not an observed response.",
              "Missing script output is unknown, not a negative vulnerability result.",
              "Script-reported findings are not independently confirmed; version/CPE matches are candidates.",
              "NSE policy excludes external/intrusive and non-safe scripts; this is not an exhaustive vulnerability audit.",
              "Nmap version probes retain their native exclusions (including TCP 9100).",
              "Unattributable aggregate states are unknown; original discovery observations remain available."]
    if meta["uid"] != 0:
        limits.append("OS detection and traceroute skipped: non-root execution.")
    else:
        limits.append("OS detection limited to hosts with open and closed TCP ports; absence of a match is unknown.")
    if target_hostname(meta["target"]):
        limits.append("Only the requested hostname context was tested; Host/SNI overrides depend on script support, not all version probes.")
    if meta["min_rate"] is not None or meta["max_retries"] is not None:
        limits.append("Explicit rate/retry overrides may reduce discovery accuracy.")
    result = {**meta, "finished": now(), "exit_code": exit_code,
              "status": "completed" if exit_code == 0 and not errors and
              all(p["status"] in ("completed", "skipped") for p in phases.values()) else "partial",
              "selected_scripts": selected, "phases": list(phases.values()),
              "hosts": list(hosts.values()), "errors": errors, "limitations": limits,
              "counts": {"discovered_open_endpoints": len(discovered),
                         "discovered_unique_tcp_ports": len({key[2] for key in discovered}),
                         "latest_observed_open_endpoints": sum(state == "open" and key[1] == "tcp"
                                                               for key, state in latest.items())}}
    version_file = directory / "nmap-version.txt"
    result["nmap_version"] = version_file.read_text() if version_file.exists() else "unknown"
    write_json(directory / "RESULTS.json", result)
    lines = [f"Nmap Cascade: {result['status']}", f"Scan: {meta['scan']}",
             f"Target: {meta['target']} | Timing: {meta['timing']}",
             f"Exit code: {exit_code}", f"NSE selection: {meta['nse_selection']}"]
    lines.extend(f"{key}: {value}" for key, value in result["counts"].items())
    lines.append("\nExecution:")
    lines.extend(f"  {p['phase']}: {p['status']} (exit {p.get('exit_code', 'n/a')})" for p in phases.values())
    for host in hosts.values():
        lines.append(f"\nHost: {host['address']}")
        for obs in host["observations"]:
            lines.append(f"  {obs['phase']} [{obs['process_status']}] {obs['started']}..{obs['finished']} — {obs['artifact']}")
            lines.append(f"    Host status: {obs['status']}")
            findings = list(obs["scripts"])
            for port in obs["ports"]:
                lines.append(f"    {port['port']}/{port['protocol']} {port['state']} service={port['service']}")
                for script in port["scripts"]:
                    findings.append({**script, "endpoint": f"{port['port']}/{port['protocol']}"})
            for script in findings:
                lines.append(f"    {script.get('endpoint', 'host')} {script['id']} [{script['interpretation']}]: {script['output']}")
                if script["reported_states"]:
                    lines.append(f"      Script-reported states: {script['reported_states']}")
            for match in obs["os_matches"]:
                lines.append(f"    OS guess: {match.get('name')} (Nmap accuracy {match.get('accuracy')}%)")
            if obs["trace"]:
                lines.append(f"    Traceroute: {obs['trace']}")
        lines.extend(f"  State change: {change}" for change in host["state_changes"])
    lines.append("\nCoverage and interpretation:")
    lines.extend(f"  - {limit}" for limit in limits)
    lines.extend(f"ERROR: {error}" for error in errors)
    (directory / "SUMMARY.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    html_path = directory / "REPORT.html"
    temporary = html_path.with_suffix(".html.tmp")
    temporary.write_text(render_report(result), encoding="utf-8")
    temporary.replace(html_path)
    if result["status"] == "partial" and exit_code == 0:
        raise ValueError("Incomplete evidence; see the partial report.")


def main():
    command, *args = sys.argv[1:]
    if command == "target":
        print(target_hostname(args[0]))
    elif command == "rate":
        rate = float(args[0])
        if not math.isfinite(rate) or rate <= 0 or not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", args[0]):
            raise ValueError("MIN_RATE must be a positive finite number.")
    elif command == "init":
        directory, scan, target, timing, uid, selection = args
        write_json(Path(directory) / "run.json", {"schema_version": 1, "scan": scan,
                   "target": target, "timing": timing, "uid": int(uid), "started": now(),
                   "nse_selection": selection, "min_rate": os.environ.get("MIN_RATE"),
                   "max_retries": os.environ.get("MAX_RETRIES")})
    elif command == "event":
        directory, phase, status, code, xml, *argv = args
        event = {"phase": phase, "status": status, "exit_code": int(code) if code else None,
                 "xml": Path(xml).name if xml else None}
        event["started" if status == "started" else "finished"] = now()
        if argv:
            event["command"] = argv
        with (Path(directory) / "events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event) + "\n")
    elif command in ("check", "jobs"):
        scan = read_scan(args[0])
        if command == "jobs":
            for host in scan["hosts"]:
                ports = open_tcp(host)
                if ports:
                    print(host["address"] + "\t" + ",".join(map(str, ports)))
    elif command == "check-selection":
        selected_scripts(args[0])
    elif command == "report":
        report(Path(args[0]), int(args[1]))
    else:
        raise ValueError(f"Unknown command: {command}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"[!] {error}", file=sys.stderr)
        sys.exit(1)
