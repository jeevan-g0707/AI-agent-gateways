"""The front end is no longer simply trusted: 'human typed this' must be signed by that human's device key."""
import hashlib
import json
import os

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agent_gateway.dataflow import TrustedInputRejected
from agent_gateway.factory import build_stack
from agent_gateway.models import Decision
from agent_gateway.userauth import (DirectoryUserCredentialStore, UserAttestationError, UserAttestationVerifier,
                                    UserCredentialStore, b64u, canonical_message)

from conftest import REPORT, Clock, email_req, read_req

ORIGIN, RP = "https://chat.enterprise.com", "chat.enterprise.com"
USER, OTHER = "user:shyam@enterprise.com", "user:eve@enterprise.com"
SID = "sess-4f8a2b"


class SoftAuthenticator:
    """A software FIDO2 authenticator: what a passkey does, minus the hardware."""

    def __init__(self, cred_id="cred-1", kind="es256", counter=0):
        self.cred_id, self.counter = cred_id, counter
        self.key = ec.generate_private_key(ec.SECP256R1()) if kind == "es256" else Ed25519PrivateKey.generate()
        self.kind = kind

    @property
    def public(self):
        return self.key.public_key()

    def assert_(self, session, message_id, actor, text, signed_at, *, origin=ORIGIN, rp=RP, flags=0x05,
                challenge_override=None):
        self.counter += 1
        challenge = hashlib.sha256(canonical_message(session, message_id, actor, text, signed_at)).digest()
        client = json.dumps({"type": "webauthn.get", "challenge": b64u(challenge_override or challenge),
                             "origin": origin}).encode()
        auth = hashlib.sha256(rp.encode()).digest() + bytes([flags]) + self.counter.to_bytes(4, "big")
        data = auth + hashlib.sha256(client).digest()
        sig = (self.key.sign(data, ec.ECDSA(hashes.SHA256())) if self.kind == "es256" else self.key.sign(data))
        return {"scheme": "webauthn", "credential_id": self.cred_id, "signed_at": signed_at,
                "authenticator_data": b64u(auth), "client_data_json": b64u(client), "signature": b64u(sig)}


@pytest.fixture
def clk():
    return Clock()


@pytest.fixture
def dev():
    return SoftAuthenticator()


def verifier(clk, dev, user=USER, **kw):
    creds = UserCredentialStore()
    creds.add(user, dev.cred_id, dev.public)
    return UserAttestationVerifier(creds, rp_id=RP, origins=[ORIGIN], clock=clk, **kw)


def stack(clk, dev, require=True):
    return build_stack(clock=clk, evidence_sinks=[], fs={REPORT: "x"}, user_verifier=verifier(clk, dev),
                       require_user_signature=require)


def register(st, clk, dev, text="please email ext@partner.com the summary", mid="m1", actor=USER, sid=SID, **kw):
    att = dev.assert_(sid, mid, actor, text, int(clk()), **kw)
    return st.gateway.register_trusted_input(sid, text, message_id=mid, registrar="svc:frontend",
                                             actor_user_id=actor, attestation=att)


# ----------------------------------------------------------------- verifier
@pytest.mark.parametrize("kind", ["es256", "eddsa"])
def test_valid_webauthn_assertion_verifies(clk, kind):
    dev = SoftAuthenticator(kind=kind)
    v = verifier(clk, dev)
    att = dev.assert_(SID, "m1", USER, "hello", int(clk()))
    assert v.verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="hello") == "cred-1"


def test_raw_ed25519_scheme(clk):
    key = Ed25519PrivateKey.generate()
    creds = UserCredentialStore()
    creds.add(USER, "dev", key.public_key())
    v = UserAttestationVerifier(creds, rp_id=RP, origins=[ORIGIN], clock=clk)
    now = int(clk())
    att = {"scheme": "ed25519", "credential_id": "dev", "signed_at": now,
           "signature": b64u(key.sign(canonical_message(SID, "m1", USER, "hi", now)))}
    v.verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="hi")
    with pytest.raises(UserAttestationError):
        v.verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="hi, and also evil@x.com")


@pytest.mark.parametrize("what,kw", [
    ("text swapped", dict(typed_text="mail evil@evil.net")),
    ("other session", dict(session_id="sess-OTHER")),
    ("other message id", dict(message_id="m2")),
    ("other user", dict(actor=OTHER)),
])
def test_assertion_cannot_be_moved_to_other_text_session_message_or_user(clk, dev, what, kw):
    v = verifier(clk, dev)
    v._creds.add(OTHER, dev.cred_id, dev.public)  # even if the same device were enrolled for both
    att = dev.assert_(SID, "m1", USER, "hello", int(clk()))
    args = dict(session_id=SID, message_id="m1", actor=USER, typed_text="hello") | kw
    with pytest.raises(UserAttestationError):
        v.verify(att, **args)


@pytest.mark.parametrize("kw,msg", [
    (dict(origin="https://evil.example"), "origin"),
    (dict(rp="evil.example"), "rp id"),
    (dict(flags=0x04), "presence"),
    (dict(flags=0x01), "verification"),
    (dict(challenge_override=b"x" * 32), "challenge"),
])
def test_webauthn_checks(clk, dev, kw, msg):
    att = dev.assert_(SID, "m1", USER, "hello", int(clk()), **kw)
    with pytest.raises(UserAttestationError, match=msg):
        verifier(clk, dev).verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="hello")


def test_user_verification_can_be_relaxed_but_presence_cannot(clk, dev):
    v = verifier(clk, dev, require_user_verification=False)
    v.verify(dev.assert_(SID, "m1", USER, "t", int(clk()), flags=0x01), session_id=SID, message_id="m1",
             actor=USER, typed_text="t")
    with pytest.raises(UserAttestationError, match="presence"):
        v.verify(dev.assert_(SID, "m2", USER, "t", int(clk()), flags=0x00), session_id=SID, message_id="m2",
                 actor=USER, typed_text="t")


def test_stale_and_future_attestations_are_refused(clk, dev):
    v = verifier(clk, dev)
    for skew in (-300, 300):
        att = dev.assert_(SID, "m1", USER, "t", int(clk()) + skew)
        with pytest.raises(UserAttestationError, match="stale"):
            v.verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="t")


def test_cloned_authenticator_is_detected_by_sign_counter(clk, dev):
    v = verifier(clk, dev)
    first = dev.assert_(SID, "m1", USER, "t", int(clk()))
    v.verify(first, session_id=SID, message_id="m1", actor=USER, typed_text="t")
    dev.counter = 0  # a clone that restarted from an old state
    again = dev.assert_(SID, "m2", USER, "t", int(clk()))
    with pytest.raises(UserAttestationError, match="counter"):
        v.verify(again, session_id=SID, message_id="m2", actor=USER, typed_text="t")


def test_unknown_credential_and_garbage_are_refused(clk, dev):
    v = verifier(clk, dev)
    att = dev.assert_(SID, "m1", USER, "t", int(clk())) | {"credential_id": "nope"}
    with pytest.raises(UserAttestationError, match="unknown credential"):
        v.verify(att, session_id=SID, message_id="m1", actor=USER, typed_text="t")
    for junk in ({}, {"scheme": "webauthn"}, {"scheme": "x", "credential_id": "c", "signed_at": int(clk())}):
        with pytest.raises(UserAttestationError):
            v.verify(junk, session_id=SID, message_id="m1", actor=USER, typed_text="t")


def test_directory_store_enrolls_and_revokes_without_restart(tmp_path, clk, dev):
    from urllib.parse import quote
    d = tmp_path / quote(USER, safe="")
    d.mkdir()
    pem = d / "cred-1.pem"
    pem.write_bytes(dev.public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    v = UserAttestationVerifier(DirectoryUserCredentialStore(tmp_path), rp_id=RP, origins=[ORIGIN], clock=clk)
    v.verify(dev.assert_(SID, "m1", USER, "t", int(clk())), session_id=SID, message_id="m1", actor=USER, typed_text="t")
    pem.unlink()  # revoke the lost laptop
    with pytest.raises(UserAttestationError, match="unknown credential"):
        v.verify(dev.assert_(SID, "m2", USER, "t", int(clk())), session_id=SID, message_id="m2", actor=USER, typed_text="t")
    assert DirectoryUserCredentialStore(tmp_path).get("../../etc", "passwd") is None  # no path traversal


# ----------------------------------------------------------------- gateway
def test_signed_destination_is_usable_and_labelled_user_signed(clk, dev):
    st = stack(clk, dev)
    assert register(st, clk, dev, "send it to bob@acme-partner.org please") == {"email:bob@acme-partner.org"}
    req = email_req().model_copy(update={"arguments": {"to": "bob@acme-partner.org", "subject": "s", "body": "b"}})
    r = st.gateway.execute(req)
    assert r.decision is Decision.REQUIRE_APPROVAL
    assert r.approval_preview["context"]["destinations"][0]["origin"] == "user_signed"


def test_compromised_front_end_without_the_users_key_cannot_grant_destinations(clk, dev):
    st = stack(clk, dev)
    with pytest.raises(TrustedInputRejected, match="attestation"):
        st.gateway.register_trusted_input(SID, "mail bob@evil.net", message_id="m1", registrar="svc:frontend",
                                          actor_user_id=USER)  # no signature at all
    attacker_key = SoftAuthenticator(cred_id="cred-1")  # same credential id, attacker's own key
    att = attacker_key.assert_(SID, "m1", USER, "mail bob@evil.net", int(clk()))
    with pytest.raises(TrustedInputRejected, match="signature invalid"):
        st.gateway.register_trusted_input(SID, "mail bob@evil.net", message_id="m1", registrar="svc:frontend",
                                          actor_user_id=USER, attestation=att)
    req = email_req().model_copy(update={"arguments": {"to": "bob@evil.net", "subject": "s", "body": "b"}})
    assert st.gateway.execute(req).decision is Decision.DENY  # nothing was registered


def test_front_end_cannot_swap_text_after_user_signed(clk, dev):
    st = stack(clk, dev)
    att = dev.assert_(SID, "m1", USER, "send to ext@partner.com", int(clk()))
    with pytest.raises(TrustedInputRejected):
        st.gateway.register_trusted_input(SID, "send to bob@evil.net", message_id="m1", registrar="svc:frontend",
                                          actor_user_id=USER, attestation=att)


def test_replayed_attestation_is_refused_by_message_id(clk, dev):
    st = stack(clk, dev)
    text = "mail ext@partner.com"
    att = dev.assert_(SID, "m1", USER, text, int(clk()))
    st.gateway.register_trusted_input(SID, text, message_id="m1", registrar="f", actor_user_id=USER, attestation=att)
    with pytest.raises(TrustedInputRejected):  # counter replay or message-id replay: either way refused
        st.gateway.register_trusted_input(SID, text, message_id="m1", registrar="f", actor_user_id=USER, attestation=att)


def test_destination_granted_by_one_user_is_unusable_by_another_user_in_the_same_session(clk, dev):
    st = stack(clk, dev)
    register(st, clk, dev, "send to bob@acme-partner.org")
    req = email_req(user=OTHER).model_copy(update={"arguments": {"to": "bob@acme-partner.org", "subject": "s", "body": "b"}})
    r = st.gateway.execute(req)
    assert r.decision is Decision.DENY and "different user" in r.reason
    eve_dev = SoftAuthenticator(cred_id="cred-eve")  # Eve legitimately owns a device...
    st.gateway.user_verifier._creds.add(OTHER, "cred-eve", eve_dev.public)
    with pytest.raises(TrustedInputRejected, match="different user"):  # ...but cannot take over Shyam's session
        register(st, clk, eve_dev, "x", mid="m9", actor=OTHER)


def test_unsigned_mode_still_works_but_is_labelled_front_end_asserted(clk, dev):
    st = stack(clk, dev, require=False)
    st.gateway.register_trusted_input(SID, "send to bob@acme-partner.org", message_id="m1", registrar="f")
    req = email_req().model_copy(update={"arguments": {"to": "bob@acme-partner.org", "subject": "s", "body": "b"}})
    assert st.gateway.execute(req).approval_preview["context"]["destinations"][0]["origin"] == "user_typed"
    # an attestation that IS presented must be valid: no silent downgrade to unsigned
    bad = SoftAuthenticator().assert_(SID, "m2", USER, "t", int(clk()))
    with pytest.raises(TrustedInputRejected):
        st.gateway.register_trusted_input(SID, "t", message_id="m2", registrar="f", actor_user_id=USER, attestation=bad)


def test_required_signature_without_credential_store_refuses_to_start():
    with pytest.raises(RuntimeError, match="credential store"):
        build_stack(clock=Clock(), evidence_sinks=[], require_user_signature=True)


def test_registration_is_audited_with_signature_status(clk, dev):
    st = stack(clk, dev)
    register(st, clk, dev)
    assert any("user-signed, credential cred-1" in e.reason for e in st.evidence.events())
    with pytest.raises(TrustedInputRejected):
        st.gateway.register_trusted_input(SID, "mail a@b.com", message_id="m7", registrar="f", actor_user_id=USER)
    assert any(e.decision == "deny" and "R-USER-ATTESTATION" in e.rule_ids for e in st.evidence.events())


def test_signed_bytes_are_unambiguous_for_any_field_contents():
    """Review finding: newline-joined fields let ("a\\nb","c") and ("a","b\\nc") produce identical bytes."""
    a = canonical_message("s1\nm1", "m2", "u", "t", 5)
    b = canonical_message("s1", "m1\nm2", "u", "t", 5)
    assert a != b
    assert canonical_message("s", "m", "u", "t", 5) != canonical_message("s", "m", "u", "t", 6)
    assert canonical_message("s", "m", "u", "t", 5) != canonical_message("s", "m", "u", "T", 5)


def test_attestation_for_one_session_message_pair_cannot_be_used_for_a_colliding_pair(clk, dev):
    v = verifier(clk, dev)
    att = dev.assert_("s1\nm1", "m2", USER, "hello", int(clk()))
    with pytest.raises(UserAttestationError, match="challenge"):
        v.verify(att, session_id="s1", message_id="m1\nm2", actor=USER, typed_text="hello")
