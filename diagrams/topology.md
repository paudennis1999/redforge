# Network topology

Three segments separated by pfSense. The attacker (Kali) is attached only to the DMZ; the internal LAN is reachable only by pivoting through a compromised DMZ host. LAN→DMZ traffic is blocked.

```mermaid
flowchart LR
  NET(("Internet / uplink<br/>NAT 192.168.240.0/24"))
  PF["pfSense<br/>firewall / router"]
  subgraph DMZ["DMZ — 172.16.10.0/24"]
    KALI["Kali<br/>172.16.10.101<br/>attacker"]
    WEB["vuln-web01<br/>172.16.10.102<br/>Ubuntu, exposed"]
  end
  subgraph LANAD["LAN / Active Directory — 172.16.20.0/24"]
    DC["DC01<br/>172.16.20.100<br/>Windows Server 2025<br/>Domain Controller + SQL Server"]
    WS["WS01<br/>domain workstation"]
  end
  NET --- PF
  PF --- DMZ
  PF --- LANAD
  DC --- WS
```
