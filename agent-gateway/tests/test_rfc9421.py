"""Stage 2: conformance against RFC 9421 Appendix B.2.6 (Ed25519) and parser edge cases."""
import base64

import pytest
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key

from agent_gateway.signing import (HTTPRequest, MessageSigner, MessageVerifier, SignatureError,
                                   content_digest, parse_signature_input)

PRIV = load_der_private_key(base64.b64decode("MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF"), None)
PUB = load_der_public_key(base64.b64decode("MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs="))
SHA512 = "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"
EXPECTED_SIG = "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"


def rfc_request():
    return HTTPRequest("POST", "https://example.com/foo?param=Value&Pet=dog", {
        "Host": "example.com", "Date": "Tue, 20 Apr 2021 02:07:55 GMT", "Content-Type": "application/json",
        "Content-Digest": SHA512, "Content-Length": "18"}, b'{"hello": "world"}')


def test_content_digest_matches_rfc():
    assert content_digest(b'{"hello": "world"}', "sha-512") == SHA512


def test_signature_matches_rfc_b26_byte_for_byte():
    out = MessageSigner("test-key-ed25519", PRIV).sign_with_params(
        rfc_request(), ["date", "@method", "@path", "@authority", "content-type", "content-length"],
        {"created": 1618884473, "keyid": "test-key-ed25519"}, "sig-b26")
    assert out.headers["Signature"] == EXPECTED_SIG
    assert out.headers["Signature-Input"] == (
        'sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");'
        'created=1618884473;keyid="test-key-ed25519"')


def test_rfc_message_verifies():
    out = MessageSigner("test-key-ed25519", PRIV).sign_with_params(
        rfc_request(), ["date", "@method", "@path", "@authority", "content-type", "content-length"],
        {"created": 1618884473, "keyid": "test-key-ed25519"}, "sig-b26")
    v = MessageVerifier({"test-key-ed25519": PUB}, clock=lambda: 1618884478, tag=None, require_nonce=False,
                        required_components=("@method", "@path", "@authority"), require_body_coverage=False)
    assert v.verify(out).key_id == "test-key-ed25519"


def test_header_tamper_in_covered_header_detected():
    out = MessageSigner("test-key-ed25519", PRIV).sign_with_params(
        rfc_request(), ["date", "@method", "@path", "@authority"], {"created": 1618884473, "keyid": "test-key-ed25519"}, "s")
    bad = out.with_headers(Date="Wed, 21 Apr 2021 02:07:55 GMT")
    v = MessageVerifier({"test-key-ed25519": PUB}, clock=lambda: 1618884478, tag=None, require_nonce=False,
                        required_components=("@method",), require_body_coverage=False)
    with pytest.raises(SignatureError, match="invalid signature"):
        v.verify(bad)


def test_parse_signature_input_roundtrip_and_malformed():
    p = parse_signature_input('a=("@method" "x-h");created=1;nonce="n\\"q";keyid="k", b=();created=2')
    assert p["a"].components == ["@method", "x-h"] and p["a"].params["nonce"] == 'n"q' and p["b"].components == []
    with pytest.raises(SignatureError):
        parse_signature_input('a=("@method')
