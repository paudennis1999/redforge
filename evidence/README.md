# Evidence

Screenshots proving each step of the kill chain, in attack order. Every capture demonstrates a specific technique rather than decorating the report.

| # | File | Step |
|---|------|------|
| 01 | `01-initial-access-ssh.png` | SSH foothold on vuln-web01 with weak credentials |
| 02 | `02-privesc-linux-and-dns-leak.png` | `sudo find` (GTFOBins) → root, and `resolvectl` DNS leak exposing the internal LAN |
| 03 | `03-pivot-ligolo.png` | ligolo-ng tunnel established, route into 172.16.20.0/24 |
| 04 | `04-target-scan-portscanner.png` | Custom `port_scanner.py` (RedForge) scanning the DC |
| 05 | `05-target-scan-nmap.png` | `nmap -sC -sV` confirming MSSQL (1433) and AD services |
| 06 | `06-mssql-sa-hydra.png` | Hydra recovering the `sa` password |
| 07 | `07-mssql-netexec-pwned.png` | netexec authenticating to MSSQL — `Pwn3d!` |
| 08 | `08-rce-xpcmdshell-ssql.png` | `xp_cmdshell whoami` → `redforge\ssql` (RCE) |
| 09 | `09-privesc-system-godpotato.png` | GodPotato (SeImpersonate) → `nt authority\system` |
| 10 | `10-ntds-dump-ntdsutil.png` | `ntdsutil` IFM snapshot of the NTDS database |
| 11 | `11-secretsdump-domain-hashes.png` | secretsdump extracting all domain hashes |
| 12 | `12-pass-the-hash-domain-admin.png` | Pass-the-Hash → evil-winrm shell as `redforge\administrator` |
| 13 | `13-defender-blocks.png` | Windows Defender protection history blocking the tooling |
| 14 | `14-bloodhound-attack-path.png` | BloodHound path: SSQL → DC01 → Administrator → Domain Admins |

Reference an image in Markdown with:

```
![Initial access](evidence/01-initial-access-ssh.png)
```
