# Custom scripts

Tooling written from scratch during the RedForge lab. These are teaching/lab tools, not production security software — use them only against systems you own or are authorized to test.

## `port_scanner.py`
Threaded TCP port scanner with host discovery. Used for recon and for finding the Domain Controller and its open services (including SQL Server on 1433) through the ligolo-ng pivot.

```
python3 port_scanner.py <target>
python3 port_scanner.py 172.16.20.0/24 --discover --workers 5
```

## `parse_kerb.py`
Parses a raw (GSS-wrapped) Kerberos ticket into hashcat format for offline cracking. Written for the Kerberoasting phase, to convert a ticket obtained via the native Windows Kerberos API into a `$krb5tgs$...` hash.

## `report_generator.py`
Helper used to support documentation and reporting during the engagement.

> Run `python3 <script> -h` for the available options.
