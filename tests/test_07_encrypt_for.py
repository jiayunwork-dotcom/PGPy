# coding=utf-8
""" Regression tests for message-level multi-recipient encryption:
``PGPMessage.encrypt_for`` and the speculative/try-all ``PGPKey.decrypt`` path.

These tests are fully offline: every key is generated in-process and no GnuPG
installation or network access is required.
"""
import copy
import warnings

import pytest

from pgpy import PGPKey
from pgpy import PGPMessage
from pgpy import PGPUID
from pgpy.constants import CompressionAlgorithm
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPEncryptionError
from pgpy.errors import PGPError
from pgpy.packet.packets import IntegrityProtectedSKEDataV1
from pgpy.packet.packets import PKESessionKeyV3

PLAINTEXT = "the session key is shared, the ciphertext is shared"
WILDCARD_KEYID = "0000000000000000"


def _make_rsa_key(name, ciphers, primary_encrypt=False, passphrase=None):
    """Build an RSA primary key with one RSA encryption subkey and explicit cipher prefs."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        uid = PGPUID.new(name, email="{:s}@example.com".format(name.lower()))
        primary_usage = {KeyFlags.Sign, KeyFlags.Certify}
        if primary_encrypt:
            primary_usage |= {KeyFlags.EncryptCommunications}
        key.add_uid(uid, usage=primary_usage,
                    hashes=[HashAlgorithm.SHA256], ciphers=list(ciphers),
                    compression=[CompressionAlgorithm.ZIP])
        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
        if passphrase is not None:
            key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


@pytest.fixture(scope="module")
def alice():
    return _make_rsa_key("Alice", [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128])


@pytest.fixture(scope="module")
def bob():
    return _make_rsa_key("Bob", [SymmetricKeyAlgorithm.AES128, SymmetricKeyAlgorithm.AES192])


@pytest.fixture(scope="module")
def carol():
    # preferences disjoint from Alice's: no AES cipher in common
    return _make_rsa_key("Carol", [SymmetricKeyAlgorithm.CAST5])


@pytest.fixture(scope="module")
def dave():
    return _make_rsa_key("Dave", [SymmetricKeyAlgorithm.AES128])


@pytest.fixture(scope="module")
def protected_alice():
    return _make_rsa_key("ProtectedAlice", [SymmetricKeyAlgorithm.AES128], passphrase="s3cr3t")


@pytest.fixture
def message():
    return PGPMessage.new(PLAINTEXT)


class TestEncryptFor(object):
    def test_two_recipients_each_decrypt(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey])

        # exactly one PKESK per recipient, plus the single shared data packet
        assert len(enc._sessionkeys) == 2
        assert all(isinstance(p, PKESessionKeyV3) for p in enc._sessionkeys)
        assert isinstance(enc.message, IntegrityProtectedSKEDataV1)

        # the PKESKs name the encryption subkeys selected by usage flags
        assert enc.encrypters == {next(iter(alice.subkeys)), next(iter(bob.subkeys))}

        assert alice.decrypt(enc).message == PLAINTEXT
        assert bob.decrypt(enc).message == PLAINTEXT

    def test_shared_session_key_and_ciphertext(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey])

        unwrapped = []
        for pkesk in enc._sessionkeys:
            for component in [alice] + list(alice.subkeys.values()) + [bob] + list(bob.subkeys.values()):
                if pkesk.encrypter == component.fingerprint.keyid:
                    unwrapped.append(pkesk.decrypt_sk(component._key))

        # every recipient recovers the same (algorithm, session key) pair
        assert len(unwrapped) == 2
        assert unwrapped[0][0] == unwrapped[1][0]
        assert bytes(unwrapped[0][1]) == bytes(unwrapped[1][1])

        # there is only ever one encrypted data packet, regardless of recipient count
        encrypted_packets = [p for p in enc if isinstance(p, IntegrityProtectedSKEDataV1)]
        assert len(encrypted_packets) == 1

    def test_duplicate_primary_recipient_collapses(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey, alice.pubkey])
        assert len(enc._sessionkeys) == 2

    def test_primary_and_its_subkey_collapse_to_one_packet(self, alice, message):
        subkey_pub = list(alice.subkeys.values())[0].pubkey
        enc = message.encrypt_for([alice.pubkey, subkey_pub])

        assert len(enc._sessionkeys) == 1
        assert enc._sessionkeys[0].encrypter == next(iter(alice.subkeys))
        assert alice.decrypt(enc).message == PLAINTEXT

    def test_primary_with_encrypt_flag_encrypts_to_itself(self, message):
        key = _make_rsa_key("SelfEncrypting", [SymmetricKeyAlgorithm.AES128], primary_encrypt=True)
        enc = message.encrypt_for([key.pubkey])

        assert len(enc._sessionkeys) == 1
        assert enc._sessionkeys[0].encrypter == key.fingerprint.keyid
        assert key.decrypt(enc).message == PLAINTEXT

    def test_cipher_is_intersection_of_preferences(self, alice, bob, message):
        # Alice: [AES256, AES128], Bob: [AES128, AES192] -> only AES128 is in both
        enc = message.encrypt_for([alice.pubkey, bob.pubkey])
        for pkesk in enc._sessionkeys:
            assert pkesk in enc._sessionkeys
        alg = enc._sessionkeys[0].decrypt_sk(alice.subkeys[next(iter(alice.subkeys))]._key)[0]
        assert alg == SymmetricKeyAlgorithm.AES128

    def test_cipher_selection_is_order_independent(self, alice, bob, message):
        enc_ab = message.encrypt_for([alice.pubkey, bob.pubkey])
        enc_ba = message.encrypt_for([bob.pubkey, alice.pubkey])

        def unwrap(enc, key):
            subkey = key.subkeys[next(iter(key.subkeys))]
            return next(p.decrypt_sk(subkey._key)[0] for p in enc._sessionkeys
                        if p.encrypter == subkey.fingerprint.keyid)

        assert unwrap(enc_ab, alice) == unwrap(enc_ba, alice) == SymmetricKeyAlgorithm.AES128

    def test_maximin_prefers_everyones_higher_choice(self, message):
        # Erin [AES256, AES128], Frank [AES256, CAST5]: intersection is {AES256, CAST5};
        # AES256 ranks first for both, CAST5 would force one recipient to their second choice
        erin = _make_rsa_key("Erin", [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128])
        frank = _make_rsa_key("Frank", [SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.CAST5])
        enc = message.encrypt_for([erin.pubkey, frank.pubkey])
        subkey = erin.subkeys[next(iter(erin.subkeys))]
        assert enc._sessionkeys[0].decrypt_sk(subkey._key)[0] == SymmetricKeyAlgorithm.AES256

    def test_empty_preference_intersection_raises(self, alice, carol, message):
        with pytest.raises(PGPEncryptionError, match="intersection"):
            message.encrypt_for([alice.pubkey, carol.pubkey])

        # nothing was encrypted on the way out
        assert not message.is_encrypted

    def test_empty_recipient_list_raises(self, message):
        with pytest.raises(PGPEncryptionError):
            message.encrypt_for([])

    def test_non_pgpkey_recipient_raises(self, message):
        with pytest.raises(TypeError):
            message.encrypt_for(["not a key"])

    def test_non_rsa_recipient_raises(self, message):
        dsa_key = PGPKey.new(PubKeyAlgorithm.DSA, 1024)
        dsa_key.add_uid(PGPUID.new("DSAOnly", email="dsa@example.com"),
                        usage={KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256],
                        ciphers=[SymmetricKeyAlgorithm.AES128])
        with pytest.raises(PGPEncryptionError):
            message.encrypt_for([dsa_key])

    def test_inputs_are_not_modified(self, alice, bob, message):
        message_snapshot = bytes(message)
        alice_snapshot = bytes(alice)
        bob_snapshot = bytes(bob)

        message.encrypt_for([alice.pubkey, bob.pubkey])

        assert bytes(message) == message_snapshot
        assert bytes(alice) == alice_snapshot
        assert bytes(bob) == bob_snapshot
        assert not message.is_encrypted

    def test_failure_leaves_inputs_untouched(self, alice, carol, message):
        snapshot = bytes(message)
        with pytest.raises(PGPEncryptionError):
            message.encrypt_for([alice.pubkey, carol.pubkey])
        assert bytes(message) == snapshot
        assert not message.is_encrypted


class TestHiddenRecipients(object):
    def test_wildcard_fields_are_all_zero(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey], hidden=True)

        assert len(enc._sessionkeys) == 2
        for pkesk in enc._sessionkeys:
            # the parsed packet exposes the eight-octet recipient field as a hex string
            assert pkesk.encrypter == WILDCARD_KEYID
            # the serialized header ends with the version octet; the body that follows
            # starts with the eight literal zero octets of the recipient field
            body = bytes(pkesk)[len(bytes(pkesk.header)):]
            assert body[:8] == b"\x00" * 8

        assert enc.encrypters == {WILDCARD_KEYID}

    def test_no_real_key_id_hidden_in_packet_bodies(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey], hidden=True)
        blob = bytes(enc)

        for key in (alice, bob):
            keyid = bytes(key.fingerprint)[-8:]
            shortid = bytes(key.fingerprint)[-4:]
            assert keyid not in blob
            assert shortid not in blob

    def test_anonymous_envelope_roundtrip_binary(self, alice, bob, message):
        enc = message.encrypt_for([alice.pubkey, bob.pubkey], hidden=True)

        reloaded = PGPMessage()
        reloaded.parse(bytes(enc))

        # all key packets survive export and re-parse
        assert len(reloaded._sessionkeys) == 2
        assert all(p.encrypter == WILDCARD_KEYID for p in reloaded._sessionkeys)

        assert alice.decrypt(reloaded).message == PLAINTEXT
        assert bob.decrypt(reloaded).message == PLAINTEXT

    def test_anonymous_envelope_roundtrip_armored(self, alice, message):
        enc = message.encrypt_for([alice.pubkey], hidden=True)
        reloaded = PGPMessage()
        reloaded.parse(str(enc))

        assert len(reloaded._sessionkeys) == 1
        assert reloaded._sessionkeys[0].encrypter == WILDCARD_KEYID
        assert alice.decrypt(reloaded).message == PLAINTEXT

    def test_hidden_envelope_rejected_for_non_recipient(self, alice, dave, message):
        enc = message.encrypt_for([dave.pubkey], hidden=True)
        with pytest.raises(PGPDecryptionError):
            alice.decrypt(enc)


class TestDecryptSearch(object):
    def test_wrong_pkesk_first_right_one_second(self, alice, dave, message):
        enc_dave = message.encrypt_for([dave.pubkey], hidden=True)
        enc_alice = message.encrypt_for([alice.pubkey], hidden=True)

        combo = PGPMessage()
        combo._sessionkeys = [copy.copy(enc_dave._sessionkeys[0]),
                              copy.copy(enc_alice._sessionkeys[0])]
        combo._message = enc_alice.message

        # Alice cannot open Dave's packet but must keep going and open her own
        assert alice.decrypt(combo).message == PLAINTEXT

    def test_recovered_session_key_failing_integrity_keeps_searching(self, alice, dave, message):
        # Dave's PKESK wraps a random session key that is NOT the one protecting the data,
        # so it unwraps successfully but fails the MDC/integrity check; Alice's packet is last
        cipher = SymmetricKeyAlgorithm.AES128
        good_key = cipher.gen_key()
        bad_key = cipher.gen_key()

        skedata = IntegrityProtectedSKEDataV1()
        skedata.encrypt(good_key, cipher, bytes(message))

        dave_subkey = dave.subkeys[next(iter(dave.subkeys))]
        pk_dave = PKESessionKeyV3()
        pk_dave.encrypter = bytearray(8)
        pk_dave.pkalg = dave_subkey.key_algorithm
        pk_dave.encrypt_sk(dave_subkey._key, cipher, bad_key)

        alice_subkey = alice.subkeys[next(iter(alice.subkeys))]
        pk_alice = PKESessionKeyV3()
        pk_alice.encrypter = bytearray(8)
        pk_alice.pkalg = alice_subkey.key_algorithm
        pk_alice.encrypt_sk(alice_subkey._key, cipher, good_key)

        mixed = PGPMessage()
        mixed._sessionkeys = [pk_dave, pk_alice]
        mixed._message = skedata

        assert alice.decrypt(mixed).message == PLAINTEXT

    def test_tampered_ciphertext_fails_for_holder(self, alice, message):
        enc = message.encrypt_for([alice.pubkey], hidden=True)
        tampered = bytearray(bytes(enc.message.ct))
        tampered[-5] ^= 0xFF
        enc.message.ct = tampered

        with pytest.raises(PGPDecryptionError):
            alice.decrypt(enc)

    def test_all_attempts_fail_raises_decryption_error(self, alice, dave, message):
        enc = message.encrypt_for([dave.pubkey], hidden=True)
        with pytest.raises(PGPDecryptionError):
            alice.decrypt(enc)

    def test_wrong_key_unpadding_never_escapes_search(self):
        # wrong-key RSA unpadding can raise ValueError, PGPDecryptionError or even an
        # IndexError on short garbage; the search must treat all of them as "try next".
        for trial in range(15):
            holder = _make_rsa_key("Holder{:d}".format(trial), [SymmetricKeyAlgorithm.AES128])
            stranger = _make_rsa_key("Stranger{:d}".format(trial), [SymmetricKeyAlgorithm.AES128])
            message = PGPMessage.new("garble {:d}".format(trial))

            # stranger's packet first (cannot open), holder's packet second (can open)
            first = message.encrypt_for([stranger.pubkey], hidden=True)
            second = message.encrypt_for([holder.pubkey], hidden=True)
            combo = PGPMessage()
            combo._sessionkeys = [copy.copy(first._sessionkeys[0]),
                                  copy.copy(second._sessionkeys[0])]
            combo._message = second.message
            assert holder.decrypt(combo).message == "garble {:d}".format(trial)

            # an envelope that is never for the holder always ends in PGPDecryptionError
            with pytest.raises(PGPDecryptionError):
                holder.decrypt(first)

    def test_named_envelope_for_other_key_preserves_pgp_error(self, alice, dave, message):
        enc = message.encrypt_for([dave.pubkey])
        with pytest.raises(PGPError, match="Cannot decrypt"):
            alice.decrypt(enc)

    def test_passphrase_protected_key_opens_anonymous_envelope(self, protected_alice, message):
        enc = message.encrypt_for([protected_alice.pubkey], hidden=True)

        # locked keys cannot decrypt
        assert protected_alice.is_protected
        with pytest.raises(PGPError):
            protected_alice.decrypt(enc)

        with protected_alice.unlock("s3cr3t"):
            decrypted = protected_alice.decrypt(enc)
        assert decrypted.message == PLAINTEXT


class TestLegacyCompatibility(object):
    def test_single_recipient_encrypt_decrypt_unchanged(self, alice, message):
        enc = alice.pubkey.encrypt(message)
        assert len(enc._sessionkeys) == 1
        assert enc._sessionkeys[0].encrypter == next(iter(alice.subkeys))
        assert alice.decrypt(enc).message == PLAINTEXT

    def test_named_nonzero_recipient_field_still_routes(self, alice, dave, message):
        enc = message.encrypt_for([alice.pubkey, dave.pubkey])
        # non-hidden envelopes keep their real Key IDs and route directly
        assert WILDCARD_KEYID not in enc.encrypters
        assert alice.decrypt(enc).message == PLAINTEXT
        assert dave.decrypt(enc).message == PLAINTEXT

    def test_legacy_encrypted_testdata_still_decrypts(self, alice):
        # a message produced through the legacy path must remain readable after re-parsing
        message = PGPMessage.new("legacy round trip")
        enc = alice.pubkey.encrypt(message)
        reloaded = PGPMessage()
        reloaded.parse(bytes(enc))
        assert alice.decrypt(reloaded).message == "legacy round trip"
