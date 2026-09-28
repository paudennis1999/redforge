#!/usr/bin/env python3
"""
Scan Report Generator
Turns a port_scanner.py JSON report (or any list of {ip, port, status, banner}
entries) into a clean, professional Markdown and/or HTML pentest report:
executive summary, per-host findings table, and risk/remediation notes for
well-known services.

Usage:
    python3 report_generator.py scan_results.json
    python3 report_generator.py scan_results.json --target "Acme Corp - External Assessment"
    python3 report_generator.py scan1.json scan2.json --output redforge_report --format both
"""

import argparse
import html
import json
import sys
from collections import defaultdict
from datetime import datetime

# Known service risk notes. Keyed by port number. Each entry is used verbatim
# in the report, so keep the wording client-ready.
SERVICE_NOTES = {
    21: ("FTP", "Medium",
         "FTP transmits credentials and data in cleartext. If required, replace with SFTP/FTPS; "
         "otherwise disable and confirm no anonymous login is allowed."),
    22: ("SSH", "Info",
         "Standard remote administration service. Verify key-based auth is enforced, root login "
         "is disabled, and the version is patched against known CVEs."),
    23: ("Telnet", "High",
         "Telnet transmits all traffic, including credentials, in cleartext. Should be disabled "
         "and replaced with SSH."),
    25: ("SMTP", "Low",
         "Mail relay service. Confirm open-relay testing has been performed and STARTTLS is enforced."),
    53: ("DNS", "Info",
         "Confirm zone transfers (AXFR) are restricted to authorized secondaries only."),
    80: ("HTTP", "Low",
         "Unencrypted web service. Should redirect to HTTPS; review for outdated software and "
         "default credentials."),
    88: ("Kerberos", "Info",
         "Indicates an Active Directory domain controller. In scope for Kerberoasting/AS-REP "
         "Roasting testing if domain credentials are available."),
    110: ("POP3", "Medium", "Cleartext mail retrieval protocol unless wrapped in TLS (POP3S, port 995)."),
    135: ("MSRPC", "Medium",
          "Windows RPC endpoint mapper. Commonly used for enumeration and lateral movement; "
          "restrict exposure to trusted networks only."),
    139: ("NetBIOS", "Medium", "Legacy SMB transport; can leak host/domain information via enumeration."),
    143: ("IMAP", "Medium", "Cleartext mail retrieval protocol unless wrapped in TLS (IMAPS, port 993)."),
    389: ("LDAP", "Medium",
          "Directory service. If unencrypted, credentials and directory data may be intercepted; "
          "prefer LDAPS (636) and enforce signing."),
    443: ("HTTPS", "Info", "Encrypted web service. Review TLS configuration, certificate validity, and headers."),
    445: ("SMB", "High",
          "Windows file sharing. Historically associated with high-impact exploits (e.g. EternalBlue) "
          "and relay attacks. Should never be exposed to untrusted networks."),
    464: ("kpasswd", "Info", "Kerberos password change service; expected alongside a domain controller."),
    636: ("LDAPS", "Info", "Encrypted directory service. Verify certificate validity and strong ciphers."),
    1433: ("MSSQL", "High",
           "SQL Server. Check for weak/default sa credentials, and note that service accounts running "
           "SQL Server with an SPN are a Kerberoasting target."),
    1521: ("Oracle DB", "High", "Oracle listener. Check for default credentials and TNS poisoning."),
    3268: ("Global Catalog", "Info", "Active Directory Global Catalog; expected on a domain controller."),
    3269: ("Global Catalog SSL", "Info", "Encrypted Global Catalog; expected on a domain controller."),
    3306: ("MySQL", "High", "Check for weak/default credentials and exposure to untrusted networks."),
    3389: ("RDP", "High",
           "Remote Desktop. Frequent target for credential brute-forcing and known CVEs (e.g. BlueKeep). "
           "Should not be internet-facing without VPN/MFA."),
    5432: ("PostgreSQL", "High", "Check for weak/default credentials and exposure to untrusted networks."),
    5900: ("VNC", "High", "Remote control protocol, often with weak or no authentication."),
    5985: ("WinRM (HTTP)", "Medium",
           "Windows Remote Management. Useful for lateral movement if credentials are obtained; "
           "should be restricted to admin workstations."),
    5986: ("WinRM (HTTPS)", "Medium", "Encrypted Windows Remote Management. Same exposure considerations as 5985."),
    6379: ("Redis", "High", "Frequently deployed without authentication; can lead to full compromise."),
    8080: ("HTTP-alt", "Low", "Alternate web service port; audit as a normal HTTP service."),
    27017: ("MongoDB", "High", "Frequently deployed without authentication; check for exposed databases."),
}

DEFAULT_NOTE = ("Unknown/Unclassified", "Info",
                "Service not in the built-in knowledge base — identify the running software and "
                "version manually and assess accordingly.")

SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def load_entries(paths):
    """Load and merge one or more scanner JSON files into a single list of entries."""
    entries = []
    for path in paths:
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"{path} does not contain a JSON list of scan entries")
        entries.extend(data)
    return entries


def group_by_host(entries):
    hosts = defaultdict(list)
    for e in entries:
        hosts[e["ip"]].append(e)
    for ip in hosts:
        hosts[ip].sort(key=lambda e: e["port"])
    return dict(sorted(hosts.items()))


def annotate(entry):
    port = entry["port"]
    service, severity, note = SERVICE_NOTES.get(port, DEFAULT_NOTE)
    return service, severity, note


def build_summary(hosts):
    total_hosts = len(hosts)
    total_open = sum(1 for h in hosts.values() for e in h if e["status"] == "open")
    total_filtered = sum(1 for h in hosts.values() for e in h if e["status"] == "filtered")

    severity_counts = defaultdict(int)
    for entries in hosts.values():
        for e in entries:
            if e["status"] != "open":
                continue
            _, severity, _ = annotate(e)
            severity_counts[severity] += 1

    return {
        "total_hosts": total_hosts,
        "total_open": total_open,
        "total_filtered": total_filtered,
        "severity_counts": severity_counts,
    }


def render_markdown(hosts, summary, target_name):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = []
    lines.append(f"# Scan Report{f' — {target_name}' if target_name else ''}")
    lines.append("")
    lines.append(f"*Generated: {now}*")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- Hosts scanned with at least one finding: **{summary['total_hosts']}**")
    lines.append(f"- Open ports discovered: **{summary['total_open']}**")
    lines.append(f"- Filtered ports discovered: **{summary['total_filtered']}**")
    lines.append("")
    if summary["severity_counts"]:
        lines.append("**Open ports by risk level:**")
        lines.append("")
        for sev in ("High", "Medium", "Low", "Info"):
            count = summary["severity_counts"].get(sev, 0)
            if count:
                lines.append(f"- {sev}: {count}")
        lines.append("")

    lines.append("## Findings by Host")
    lines.append("")

    for ip, entries in hosts.items():
        lines.append(f"### {ip}")
        lines.append("")
        lines.append("| Port | Status | Service | Risk | Banner |")
        lines.append("|------|--------|---------|------|--------|")
        sorted_entries = sorted(
            entries,
            key=lambda e: (SEVERITY_ORDER.get(annotate(e)[1], 9) if e["status"] == "open" else 9, e["port"]),
        )
        for e in sorted_entries:
            service, severity, _ = annotate(e)
            banner = (e.get("banner") or "").replace("|", "\\|") or "-"
            lines.append(f"| {e['port']} | {e['status']} | {service} | {severity} | {banner} |")
        lines.append("")

        open_entries = [e for e in entries if e["status"] == "open"]
        if open_entries:
            lines.append("**Notes & Recommendations:**")
            lines.append("")
            for e in sorted(open_entries, key=lambda e: SEVERITY_ORDER.get(annotate(e)[1], 9)):
                service, severity, note = annotate(e)
                lines.append(f"- **{e['port']}/{service}** ({severity}) — {note}")
            lines.append("")

    return "\n".join(lines)


def render_html(hosts, summary, target_name):
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    esc = html.escape

    severity_colors = {
        "High": "#dc2626",
        "Medium": "#d97706",
        "Low": "#2563eb",
        "Info": "#6b7280",
    }

    parts = []
    parts.append(f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Scan Report{f' - {esc(target_name)}' if target_name else ''}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; color: #1f2937; }}
  h1 {{ border-bottom: 3px solid #111827; padding-bottom: 8px; }}
  h2 {{ margin-top: 40px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; }}
  h3 {{ margin-top: 28px; color: #111827; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0 20px; }}
  th, td {{ border: 1px solid #e5e7eb; padding: 6px 10px; text-align: left; font-size: 14px; }}
  th {{ background: #f9fafb; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; font-weight: 600; }}
  .summary-list {{ line-height: 1.8; }}
  .banner {{ font-family: monospace; font-size: 12px; color: #4b5563; }}
  ul.notes li {{ margin-bottom: 6px; }}
  .meta {{ color: #6b7280; font-size: 13px; }}
</style>
</head>
<body>
<h1>Scan Report{f' &mdash; {esc(target_name)}' if target_name else ''}</h1>
<p class="meta">Generated: {now}</p>

<h2>Executive Summary</h2>
<ul class="summary-list">
  <li>Hosts scanned with at least one finding: <strong>{summary['total_hosts']}</strong></li>
  <li>Open ports discovered: <strong>{summary['total_open']}</strong></li>
  <li>Filtered ports discovered: <strong>{summary['total_filtered']}</strong></li>
</ul>
""")

    if summary["severity_counts"]:
        parts.append("<p><strong>Open ports by risk level:</strong></p><ul class=\"summary-list\">")
        for sev in ("High", "Medium", "Low", "Info"):
            count = summary["severity_counts"].get(sev, 0)
            if count:
                color = severity_colors[sev]
                parts.append(
                    f'<li><span class="badge" style="background:{color}">{sev}</span> {count}</li>'
                )
        parts.append("</ul>")

    parts.append("<h2>Findings by Host</h2>")

    for ip, entries in hosts.items():
        parts.append(f"<h3>{esc(ip)}</h3>")
        parts.append("<table><tr><th>Port</th><th>Status</th><th>Service</th><th>Risk</th><th>Banner</th></tr>")
        sorted_entries = sorted(
            entries,
            key=lambda e: (SEVERITY_ORDER.get(annotate(e)[1], 9) if e["status"] == "open" else 9, e["port"]),
        )
        for e in sorted_entries:
            service, severity, _ = annotate(e)
            color = severity_colors.get(severity, "#6b7280")
            banner = esc(e.get("banner") or "-")
            parts.append(
                f"<tr><td>{e['port']}</td><td>{e['status']}</td><td>{esc(service)}</td>"
                f'<td><span class="badge" style="background:{color}">{severity}</span></td>'
                f'<td class="banner">{banner}</td></tr>'
            )
        parts.append("</table>")

        open_entries = [e for e in entries if e["status"] == "open"]
        if open_entries:
            parts.append("<p><strong>Notes &amp; Recommendations:</strong></p><ul class=\"notes\">")
            for e in sorted(open_entries, key=lambda e: SEVERITY_ORDER.get(annotate(e)[1], 9)):
                service, severity, note = annotate(e)
                parts.append(f"<li><strong>{e['port']}/{esc(service)}</strong> ({severity}) &mdash; {esc(note)}</li>")
            parts.append("</ul>")

    parts.append("</body></html>")
    return "\n".join(parts)


def main():
    parser = argparse.ArgumentParser(description="Generate a professional report from port_scanner.py JSON output")
    parser.add_argument("inputs", nargs="+", help="One or more JSON scan result files")
    parser.add_argument("--target", default=None, help="Friendly name for the target/engagement, shown in the title")
    parser.add_argument("--output", default="report", help="Output file base name (without extension)")
    parser.add_argument("--format", choices=["md", "html", "both"], default="both", help="Output format(s)")
    args = parser.parse_args()

    try:
        entries = load_entries(args.inputs)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"[!] Error loading input: {e}", file=sys.stderr)
        sys.exit(1)

    if not entries:
        print("[!] No entries found in the provided file(s).", file=sys.stderr)
        sys.exit(1)

    hosts = group_by_host(entries)
    summary = build_summary(hosts)

    if args.format in ("md", "both"):
        md = render_markdown(hosts, summary, args.target)
        md_path = f"{args.output}.md"
        with open(md_path, "w") as f:
            f.write(md)
        print(f"[*] Markdown report written to {md_path}")

    if args.format in ("html", "both"):
        html_out = render_html(hosts, summary, args.target)
        html_path = f"{args.output}.html"
        with open(html_path, "w") as f:
            f.write(html_out)
        print(f"[*] HTML report written to {html_path}")


if __name__ == "__main__":
    main()
