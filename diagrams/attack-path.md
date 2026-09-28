# Attack path

Full kill chain from a DMZ foothold to domain compromise. Each phase enables the next; the pivot through pfSense is the only bridge into the internal network. Tactic labels map to MITRE ATT&CK.

```mermaid
flowchart TD
  A["1 · Initial Access<br/>SSH weak credentials → foothold on vuln-web01"] --> B["2 · Privilege Escalation (Linux)<br/>sudo find NOPASSWD (GTFOBins) → root"]
  B --> C["3 · Discovery<br/>DNS leak via resolvectl → internal LAN 172.16.20.0/24 revealed"]
  C --> D{"Pivot / Lateral Movement<br/>ligolo-ng through pfSense · DMZ → LAN"}
  D --> E["4 · Execution<br/>SQL Server 'sa' weak password + xp_cmdshell → RCE as domain account ssql"]
  E --> F["5 · Privilege Escalation<br/>SeImpersonatePrivilege + GodPotato → NT AUTHORITY\SYSTEM on the DC"]
  F --> G["6 · Credential Access<br/>ntdsutil (VSS snapshot) + secretsdump → NTDS.dit domain hashes"]
  G --> H["7 · Impact — Domain Compromise<br/>Administrator + krbtgt → Pass-the-Hash as Domain Admin"]
```

## BloodHound path

The privileged relationship confirmed during AD enumeration:

```
SSQL --[SQLAdmin]--> DC01 --[HasSession]--> Administrator --[MemberOf]--> Domain Admins
```
