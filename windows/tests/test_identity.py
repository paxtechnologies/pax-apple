# SPDX-License-Identifier: GPL-3.0-only
import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

import pax_device
from pax_windows import identity


def test_identity_like_the_mac_recipe(tmp_path):
    ident = identity.create(tmp_path / "id")
    cert = x509.load_der_x509_certificate(ident.certificate.read_bytes())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "Pax Supervision Identity"
    assert cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == "Pax"
    assert cert.issuer == cert.subject
    life = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert dt.timedelta(days=3649) < life <= dt.timedelta(days=3650)
    key = serialization.load_der_private_key(ident.private_key.read_bytes(), password=None)
    assert key.key_size == 2048
    # The shared helper turns this pair into the keybag for the silent install.
    pem = pax_device._keybag_pem(ident.certificate.read_bytes(), ident.private_key.read_bytes())
    assert b"BEGIN CERTIFICATE" in pem and b"BEGIN RSA PRIVATE KEY" in pem


def test_destroy(tmp_path):
    ident = identity.create(tmp_path)
    identity.destroy_private_key(ident)
    assert not ident.private_key.exists() and ident.certificate.exists()
    identity.destroy_private_key(ident)            # twice is fine
