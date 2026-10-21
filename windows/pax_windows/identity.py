# SPDX-License-Identifier: GPL-3.0-only
"""The throw-away supervision identity (Mac: SupervisionIdentityStore in
mac-app/Sources/PaxCore/Supporting.swift, which runs /usr/bin/openssl). Windows has no
openssl, so the same identity is made with the `cryptography` package Pax already
bundles: RSA 2048, self-signed, CN=Pax Supervision Identity, O=Pax, 3650 days, written as
DER. The private key is overwritten and deleted once the profile is installed: whoever
holds it could manage the supervised phone, so keeping it would hand a way around the
lock to anyone using this PC."""
from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SupervisionIdentity:
    certificate: Path
    private_key: Path


def create(folder: Path) -> SupervisionIdentity:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Pax Supervision Identity"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pax")])
    now = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path = folder / "identity-cert.der"
    key_path = folder / "identity-key.der"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, key.private_bytes(serialization.Encoding.DER,
                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))
    finally:
        os.close(fd)
    return SupervisionIdentity(cert_path, key_path)


def destroy_private_key(identity: SupervisionIdentity) -> None:
    """Best-effort overwrite, then delete (as SecureFile.overwriteAndDelete on the Mac)."""
    p = identity.private_key
    try:
        size = p.stat().st_size
        with open(p, "r+b") as f:
            f.write(b"\0" * size)
            f.flush()
            os.fsync(f.fileno())
    except OSError:
        pass
    try:
        p.unlink()
    except OSError:
        pass
