#!/usr/bin/env python3
"""
Multi-recipient encryption example for ``PGPMessage.encrypt_for``.

Runs fully offline: two RSA keys are generated in-process, a message is
encrypted once to both recipients (first visibly, then with hidden/wildcard
recipient fields), and each recipient independently decrypts it. Duplicate
recipients, the empty-preference-intersection error, and the all-attempts-fail
case are also demonstrated.

Run it with:  python3 examples/encrypt_for_multiple_recipients.py
"""
import os
import sys

# allow running straight from a source checkout without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pgpy import PGPKey  # noqa: E402
from pgpy import PGPMessage  # noqa: E402
from pgpy import PGPUID  # noqa: E402
from pgpy.constants import CompressionAlgorithm  # noqa: E402
from pgpy.constants import HashAlgorithm  # noqa: E402
from pgpy.constants import KeyFlags  # noqa: E402
from pgpy.constants import PubKeyAlgorithm  # noqa: E402
from pgpy.constants import SymmetricKeyAlgorithm  # noqa: E402
from pgpy.errors import PGPDecryptionError  # noqa: E402
from pgpy.errors import PGPEncryptionError  # noqa: E402


def make_rsa_key(name, cipher_prefs):
    """Generate an RSA key with a sign-only primary and an RSA encryption subkey."""
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    uid = PGPUID.new(name, email="{:s}@example.com".format(name.lower()))
    key.add_uid(uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256],
                ciphers=cipher_prefs,
                compression=[CompressionAlgorithm.ZIP])

    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    return key


def heading(text):
    print("\n" + "=" * 72)
    print(text)
    print("=" * 72)


def main():
    # Two recipients with overlapping preferences:
    #   Alice: AES-256, AES-128     Bob: AES-128, AES-192
    # The only cipher in both preference lists is AES-128.
    alice = make_rsa_key("Alice", [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128])
    bob = make_rsa_key("Bob", [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES192])

    plaintext = "one envelope, one session key, every recipient can read it"
    message = PGPMessage.new(plaintext)

    heading("1. Encrypt one message to both public keys")
    envelope = message.encrypt_for([alice.pubkey, bob.pubkey])
    print("PKESK packets:        {:d} (one per distinct receiving key)".format(len(envelope._sessionkeys)))
    print("Recipient Key IDs:    {}".format(sorted(envelope.encrypters)))
    print("Both point at the encryption subkeys selected by the usage flags.")

    for holder in (alice, bob):
        decrypted = holder.decrypt(envelope)
        print("{:6s} decrypted -> {!r}".format(holder.userids[0].name, decrypted.message))
        assert decrypted.message == plaintext

    heading("2. Passing the same key twice does not add another packet")
    repeated = message.encrypt_for([alice.pubkey, alice.pubkey, bob.pubkey])
    print("PKESK packets:        {:d} (duplicates collapse)".format(len(repeated._sessionkeys)))
    assert len(repeated._sessionkeys) == 2

    heading("3. Hidden recipients: zeroed recipient fields")
    hidden = message.encrypt_for([alice.pubkey, bob.pubkey], hidden=True)
    for pkesk in hidden._sessionkeys:
        print("  recipient field -> {}".format(pkesk.encrypter))
        assert pkesk.encrypter == "0000000000000000"

    # export the envelope and read it back; no key packet is lost and no
    # real Key ID is carried anywhere in the bytes
    blob = bytes(hidden)
    reloaded = PGPMessage()
    reloaded.parse(blob)
    print("Packets after round-trip: {:d} (unchanged)".format(len(reloaded._sessionkeys)))
    for holder in (alice, bob):
        decrypted = holder.decrypt(reloaded)
        print("{:6s} decrypted hidden envelope -> {!r}".format(holder.userids[0].name, decrypted.message))
        assert decrypted.message == plaintext

    heading("4. Empty preference intersection is a hard error")
    # Carol only accepts CAST5; Alice only lists AES ciphers -> no common cipher
    carol = make_rsa_key("Carol", [SymmetricKeyAlgorithm.CAST5])
    try:
        message.encrypt_for([alice.pubkey, carol.pubkey])
    except PGPEncryptionError as exc:
        print("Refused to encrypt: {}".format(exc))
    else:  # pragma: no cover
        raise AssertionError("expected PGPEncryptionError")

    heading("5. A key that is not a recipient cannot open the envelope")
    outsider = make_rsa_key("Outsider", [SymmetricKeyAlgorithm.AES128])
    try:
        outsider.decrypt(hidden)
    except PGPDecryptionError as exc:
        print("Decryption refused: {}".format(exc))
    else:  # pragma: no cover
        raise AssertionError("expected PGPDecryptionError")

    print("\nAll checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
