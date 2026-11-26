# coding=utf-8
""" Regression tests for the lifetime of temporarily unlocked private key material.

All keys are generated in-process (RSA) and every check runs without GnuPG or
network access.

The bugs being fixed, all of which stemmed from unlock state living in mutable
per-object material instead of being tied to explicit scopes:

 * an inner ``unlock`` scope (normal exit or wrong passphrase) tore down the
   outer scope's decrypted material;
 * a ``copy.copy`` made while unlocked kept its plaintext after the scope it
   was copied in had exited;
 * unlocking a protected primary key zeroed the private parameters of
   subkeys that were never encrypted in the first place;
 * unlocking could change the exported bytes of a protected key.
"""
import copy

import pytest

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from cryptography.hazmat.primitives import hashes
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPError

PASSPHRASE = "correct horse battery staple"
WRONG_PASSPHRASE = "definitely not the passphrase"


def _make_rsa_key(protected=True, with_subkey=True, subkey_protected=True):
    """Generate an RSA private key (1024-bit, fast for tests) with an optional RSA signing subkey."""
    uid = PGPUID.new("Unlock Lifetime", email="unlock-lifetime@example.com")
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256])

    if with_subkey:
        subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        key.add_subkey(subkey, usage={KeyFlags.Sign})

    if protected:
        if with_subkey and not subkey_protected:
            # protect only the primary key packet; the subkey stays plaintext
            key._key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        else:
            key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return key


def _assert_signs(key, message=b"data"):
    sig = key.sign(message)
    # the signature must actually verify against the public half
    assert key.pubkey.verify(message, sig)


def _assert_cannot_sign(key):
    with pytest.raises(PGPError):
        key.sign(b"data")


class TestSingleUnlock:
    def test_normal_single_unlock(self):
        key = _make_rsa_key()
        assert key.is_protected
        assert key.is_unlocked is False
        _assert_cannot_sign(key)

        with key.unlock(PASSPHRASE):
            assert key.is_unlocked
            _assert_signs(key)
            for subkey in key.subkeys.values():
                assert subkey.is_unlocked
                _assert_signs(subkey)

        assert key.is_unlocked is False
        _assert_cannot_sign(key)
        for subkey in key.subkeys.values():
            assert subkey.is_unlocked is False
            _assert_cannot_sign(subkey)

    def test_wrong_passphrase_never_unlocks(self):
        key = _make_rsa_key()
        with pytest.raises(PGPDecryptionError):
            with key.unlock(WRONG_PASSPHRASE):
                pass  # pragma: no cover - entering must raise
        assert key.is_unlocked is False
        _assert_cannot_sign(key)
        # the key must still be usable with the correct passphrase afterwards
        with key.unlock(PASSPHRASE):
            _assert_signs(key)


class TestNestedUnlock:
    def test_inner_scope_exit_keeps_outer_scope_alive(self):
        key = _make_rsa_key()

        with key.unlock(PASSPHRASE):
            _assert_signs(key)
            with key.unlock(PASSPHRASE):
                _assert_signs(key)
            # the inner scope exiting must not revoke the outer scope
            assert key.is_unlocked
            _assert_signs(key)

        assert key.is_unlocked is False
        _assert_cannot_sign(key)

    def test_failed_inner_scope_keeps_outer_scope_alive(self):
        # A wrong passphrase can only surface while material still has to be decrypted, i.e. on a packet that
        # the outer scope does not cover. Build that situation explicitly with a second, still-locked key and
        # then prove the outer scope on the first key is untouched by the failed attempt.
        outer_key = _make_rsa_key()
        locked_key = _make_rsa_key()
        subkey = next(iter(outer_key.subkeys.values()))

        with outer_key.unlock(PASSPHRASE):
            with pytest.raises(PGPDecryptionError):
                with locked_key.unlock(WRONG_PASSPHRASE):
                    pass  # pragma: no cover - entering must raise

            # the unrelated failure must not have torn down the outer scope
            assert outer_key.is_unlocked
            assert subkey.is_unlocked
            _assert_signs(outer_key)
            _assert_signs(subkey)

            # nested re-entry on the already-unlocked key neither re-derives keys nor can fail
            with outer_key.unlock(WRONG_PASSPHRASE):
                _assert_signs(outer_key)

        assert outer_key.is_unlocked is False
        assert subkey.is_unlocked is False
        _assert_cannot_sign(outer_key)
        _assert_cannot_sign(subkey)

    def test_exception_in_inner_body_keeps_outer_scope_alive(self):
        key = _make_rsa_key()

        with key.unlock(PASSPHRASE):
            with pytest.raises(RuntimeError):
                with key.unlock(PASSPHRASE):
                    raise RuntimeError("boom")
            _assert_signs(key)

        _assert_cannot_sign(key)

    def test_holder_counter_balanced_after_mixed_scopes(self):
        key = _make_rsa_key()
        material = key._key.keymaterial

        with key.unlock(PASSPHRASE):
            with key.unlock(PASSPHRASE):
                pass
            # re-entering an active scope adds and removes one holder without decrypting again
            with key.unlock(WRONG_PASSPHRASE):
                pass
            assert material._unlock_state.holders == 1

        assert material._unlock_state.holders == 0

    def test_failed_entry_rolls_back_its_own_holds(self):
        key = _make_rsa_key()
        primary_material = key._key.keymaterial
        subkey_material = next(iter(key.subkeys.values()))._key.keymaterial

        with pytest.raises(PGPDecryptionError):
            with key.unlock(WRONG_PASSPHRASE):
                pass  # pragma: no cover

        # nothing remains locked-but-decrypted; both packets are back to zero holders
        assert primary_material._unlock_state.holders == 0
        assert subkey_material._unlock_state.holders == 0

    def test_failure_on_a_later_packet_rolls_back_already_decrypted_one(self):
        key = _make_rsa_key()
        subkey = next(iter(key.subkeys.values()))
        primary_material = key._key.keymaterial
        subkey_material = subkey._key.keymaterial

        def boom(passphrase):
            raise PGPDecryptionError("simulated subkey decryption failure")

        # the primary packet decrypts fine; force the subkey packet to fail afterwards
        subkey._key.unprotect = boom
        with pytest.raises(PGPDecryptionError):
            with key.unlock(PASSPHRASE):
                pass  # pragma: no cover

        # the primary packet's hold must have been rolled back, leaving no plaintext behind
        assert primary_material._unlock_state.holders == 0
        assert subkey_material._unlock_state.holders == 0
        assert key.is_unlocked is False
        _assert_cannot_sign(key)

        # a subsequent healthy unlock still works
        subkey._key.unprotect = lambda passphrase: type(subkey._key).unprotect(subkey._key, passphrase)
        with key.unlock(PASSPHRASE):
            _assert_signs(key)


class TestUnlockAndCopies:
    def test_copy_inside_scope_works_then_is_locked(self):
        key = _make_rsa_key()

        with key.unlock(PASSPHRASE):
            snapshot = copy.copy(key)
            # the copy can do everything the original can at this moment
            assert snapshot.is_unlocked
            _assert_signs(snapshot)
            assert snapshot._key.keymaterial._unlock_state is key._key.keymaterial._unlock_state

        # once every covering scope has exited, the copy must not retain usable plaintext
        assert snapshot.is_unlocked is False
        _assert_cannot_sign(snapshot)
        _assert_cannot_sign(key)

    def test_subkey_reference_taken_inside_scope_has_same_lifetime(self):
        key = _make_rsa_key()

        with key.unlock(PASSPHRASE):
            subkey_ref = next(iter(key.subkeys.values()))
            _assert_signs(subkey_ref)

        _assert_cannot_sign(subkey_ref)
        # re-unlocking restores it
        with key.unlock(PASSPHRASE):
            _assert_signs(subkey_ref)

    def test_copy_made_while_locked_is_not_unlocked_by_original(self):
        key = _make_rsa_key()
        locked_snapshot = copy.copy(key)
        assert locked_snapshot.is_unlocked is False

        with key.unlock(PASSPHRASE):
            # the original's scope must not leak into a copy that predates it
            assert locked_snapshot.is_unlocked is False
            _assert_cannot_sign(locked_snapshot)
            _assert_signs(key)

        # the independent copy can still be unlocked on its own
        with locked_snapshot.unlock(PASSPHRASE):
            _assert_signs(locked_snapshot)
        _assert_cannot_sign(locked_snapshot)

    def test_copy_of_subkey_inside_scope_is_cleaned_with_it(self):
        key = _make_rsa_key()

        with key.unlock(PASSPHRASE):
            subkey = next(iter(key.subkeys.values()))
            # copy the subkey's private key packet, which shares the unlock state of its source
            subkey_packet_copy = copy.copy(subkey._key)
            assert subkey_packet_copy.keymaterial._unlock_state is subkey._key.keymaterial._unlock_state
            subkey_packet_copy.sign(b"data", hashes.SHA256())

        # no plaintext survives in the copy once every covering scope has exited
        with pytest.raises(PGPError):
            subkey_packet_copy.sign(b"data", hashes.SHA256())
        with pytest.raises(PGPError):
            subkey.sign(b"data")


class TestUnencryptedSubkeys:
    def test_unencrypted_subkey_survives_unlock_exit(self):
        key = _make_rsa_key(protected=True, subkey_protected=False)
        subkey = next(iter(key.subkeys.values()))

        assert key.is_protected
        assert subkey.is_protected is False
        _assert_signs(subkey)

        with key.unlock(PASSPHRASE):
            _assert_signs(key)
            _assert_signs(subkey)

        # the never-encrypted subkey must remain fully usable
        assert subkey.is_unlocked
        _assert_signs(subkey)

    def test_unencrypted_subkey_survives_failed_unlock(self):
        key = _make_rsa_key(protected=True, subkey_protected=False)
        subkey = next(iter(key.subkeys.values()))

        with pytest.raises(PGPDecryptionError):
            with key.unlock(WRONG_PASSPHRASE):
                pass  # pragma: no cover

        _assert_signs(subkey)

    def test_unencrypted_key_unlock_is_a_noop_warning(self):
        key = _make_rsa_key(protected=False)
        subkey = next(iter(key.subkeys.values()))

        with pytest.warns(UserWarning):
            with key.unlock("anything"):
                _assert_signs(key)
                _assert_signs(subkey)

        _assert_signs(key)
        _assert_signs(subkey)


class TestExportsAndReuse:
    def test_exported_bytes_unchanged_by_unlocking(self):
        key = _make_rsa_key()
        before = bytes(key)

        with key.unlock(PASSPHRASE):
            _assert_signs(key)
            # exporting while unlocked must serialize the ciphertext, never plaintext
            assert bytes(key) == before

        assert bytes(key) == before

    def test_reloaded_key_unlocks_and_signs(self):
        key = _make_rsa_key()
        exported = bytes(key)

        reloaded = PGPKey()
        reloaded.parse(bytearray(exported))
        assert reloaded.is_protected
        _assert_cannot_sign(reloaded)

        with reloaded.unlock(PASSPHRASE):
            _assert_signs(reloaded)

        _assert_cannot_sign(reloaded)

    def test_repeated_unlock_cycles(self):
        key = _make_rsa_key()
        for _ in range(3):
            assert key.is_unlocked is False
            with key.unlock(PASSPHRASE):
                _assert_signs(key)
            assert key.is_unlocked is False
        _assert_cannot_sign(key)


class TestExplicitUnavailableErrors:
    def test_signing_after_scope_raises_pgp_error_not_crypto_error(self):
        key = _make_rsa_key()
        with key.unlock(PASSPHRASE):
            _assert_signs(key)

        with pytest.raises(PGPError):
            key.sign(b"data")

    def test_packet_level_sign_guards_material_state(self):
        key = _make_rsa_key()
        material = key._key.keymaterial
        with pytest.raises(PGPError):
            material.sign(b"data", hashes.SHA256())

        with key.unlock(PASSPHRASE):
            material.sign(b"data", hashes.SHA256())

        with pytest.raises(PGPError):
            material.sign(b"data", hashes.SHA256())
