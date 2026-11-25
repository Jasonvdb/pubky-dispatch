#!/usr/bin/env python3
"""The loopback TLS test fixture: a CA certificate and a server certificate for
`localhost`, made from two Ed25519 keys of the key vectors, byte for byte the same
for the same inputs. Ed25519 signs deterministically, and every other field is fixed:
serials 1 and 2, validity 2020-01-01 to 2099-01-01, the same extensions in the same
order. Signs with `openssl pkeyutl`.

usage: rename-bytes-tls.py CA_SECRET_HEX SERVER_SECRET_HEX CA_NAME
prints three base64url lines: the CA certificate, the server certificate, the
server's PKCS#8 key."""
import base64, hashlib, os, subprocess, sys, tempfile

def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body

seq = lambda *parts: tlv(0x30, b"".join(parts))
oid = lambda der: tlv(0x06, der)
ED25519 = seq(oid(bytes.fromhex("2b6570")))

def pkcs8(secret):
    return bytes.fromhex("302e020100300506032b657004220420") + secret

def public(secret):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "k.der")
        open(path, "wb").write(pkcs8(secret))
        out = subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", path, "-pubout", "-outform", "DER"],
                             check=True, stdout=subprocess.PIPE).stdout
    return out[-32:]

def sign(secret, data):
    with tempfile.TemporaryDirectory() as d:
        key, msg = os.path.join(d, "k.der"), os.path.join(d, "m")
        open(key, "wb").write(pkcs8(secret))
        open(msg, "wb").write(data)
        return subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER", "-inkey", key, "-in", msg],
                              check=True, stdout=subprocess.PIPE).stdout

def name(cn):
    return seq(tlv(0x31, seq(oid(bytes.fromhex("550403")), tlv(0x0c, cn.encode()))))

def ext(oid_hex, value, critical=False):
    return seq(oid(bytes.fromhex(oid_hex)), *( [tlv(0x01, b"\xff")] if critical else [] ), tlv(0x04, value))

def cert(serial, issuer, subject, subject_public, issuer_secret, extensions):
    validity = seq(tlv(0x17, b"200101000000Z"), tlv(0x18, b"20990101000000Z"))
    spki = seq(ED25519, tlv(0x03, b"\x00" + subject_public))
    tbs = seq(tlv(0xa0, tlv(0x02, b"\x02")), tlv(0x02, bytes([serial])), ED25519, issuer, validity,
              subject, spki, tlv(0xa3, seq(*extensions)))
    return seq(tbs, ED25519, tlv(0x03, b"\x00" + sign(issuer_secret, tbs)))

def key_id(public_key):
    return hashlib.sha1(public_key).digest()

def main():
    ca_secret, server_secret = bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2])
    ca_name = name(sys.argv[3])
    ca_public, server_public = public(ca_secret), public(server_secret)
    ca_id = key_id(ca_public)
    aki = seq(tlv(0x80, ca_id))
    ca = cert(1, ca_name, ca_name, ca_public, ca_secret, [
        ext("551d0e", tlv(0x04, ca_id)),
        ext("551d23", aki),
        ext("551d13", seq(tlv(0x01, b"\xff")), critical=True),
        ext("551d0f", tlv(0x03, b"\x02\x04"), critical=True),
    ])
    server = cert(2, ca_name, name("localhost"), server_public, ca_secret, [
        ext("551d13", seq(), critical=True),
        ext("551d0f", tlv(0x03, b"\x07\x80"), critical=True),
        ext("551d25", seq(oid(bytes.fromhex("2b06010505070301")))),
        ext("551d11", seq(tlv(0x82, b"localhost"))),
        ext("551d0e", tlv(0x04, key_id(server_public))),
        ext("551d23", aki),
    ])
    for der in (ca, server, pkcs8(server_secret)):
        print(base64.urlsafe_b64encode(der).decode().rstrip("="))

main()
