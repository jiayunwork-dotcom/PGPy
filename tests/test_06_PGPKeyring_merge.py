# coding=utf-8
""" test PGPKeyring.load(merge=True) and PGPKey.merge

These tests use keys generated in-process; no GnuPG and no network access are required.
"""
import pytest

from datetime import datetime, timezone

from pgpy import PGPKey
from pgpy import PGPKeyring
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import RevocationReason
from pgpy.constants import SignatureType
from pgpy.types import Fingerprint


def inventory(key):
    """An order-insensitive inventory of all of a key's packets, grouped by their owner.

    Packets are compared by their exact serialized bytes; embedded signatures are carried
    within their parent signature's bytes, so they are not listed separately.
    """
    return {
        'primary': bytes(key._key),
        'sigs': sorted(bytes(s) for s in key._signatures if not s.embedded),
        'uids': {bytes(u._uid): sorted(bytes(s) for s in u._signatures) for u in key._uids},
        'subkeys': {sk.fingerprint: (bytes(sk._key),
                                     sorted(bytes(s) for s in sk._signatures if not s.embedded))
                    for sk in key.subkeys.values()},
    }


def keyring_snapshot(kr):
    """A snapshot of a keyring's contents and lookup index, for before/after comparison."""
    return (len(kr),
            len(kr._pubkeys),
            len(kr._privkeys),
            {k.fingerprint for k in kr._keys.values()},
            {alias for m in kr._aliases for alias in m})


class _ns(object):
    pass


@pytest.fixture(scope='module')
def alice():
    """A private key built in stages, snapshotting two partial public exports of itself.

    blobA (the "earlier" export): uid1 + sub1
    blobB (the "later" export):   uid1 (now also carrying a certification revocation),
                                  uid2, sub1 (now also carrying a subkey revocation), sub2
    """
    ns = _ns()
    ns.email1 = 'alice@example.com'
    ns.email2 = 'alice.a@example.com'

    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid1 = PGPUID.new('Alice Aardvark', email=ns.email1)
    key.add_uid(uid1, usage={KeyFlags.Certify, KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    sub1 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub1, usage={KeyFlags.EncryptCommunications})
    ns.blobA = bytes(key.pubkey)
    ns.privblobA = bytes(key)

    uid2 = PGPUID.new('Alice A', email=ns.email2)
    key.add_uid(uid2, usage={KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])
    sub2 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub2, usage={KeyFlags.EncryptCommunications})
    sub1 |= key.revoke(sub1, reason=RevocationReason.Retired, comment='superseded')
    uid1 |= key.revoke(uid1)
    ns.blobB = bytes(key.pubkey)

    ns.priv = key
    ns.privblob = bytes(key)
    ns.fp = key.fingerprint
    ns.sub1fp = sub1.fingerprint
    ns.sub2fp = sub2.fingerprint
    return ns


@pytest.fixture(scope='module')
def bob():
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid = PGPUID.new('Bob Baker', email='bob@example.com')
    key.add_uid(uid, usage={KeyFlags.Certify, KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    return key


@pytest.fixture(scope='module')
def bob_certs(alice, bob):
    """Two third-party certifications of alice's first UID by bob, with the same creation
    time but different contents (different hash algorithms), and therefore different bytes."""
    kA, _ = PGPKey.from_blob(alice.blobA)
    uid = kA.userids[0]
    when = datetime(2020, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    cert1 = bob.certify(uid, level=SignatureType.Positive_Cert, hash=HashAlgorithm.SHA256, created=when)
    cert2 = bob.certify(uid, level=SignatureType.Positive_Cert, hash=HashAlgorithm.SHA512, created=when)
    return cert1, cert2


def get_uid(key, email):
    return next(u for u in key.userids if u.email == email)


class TestPGPKeyMerge(object):
    def test_merge_requires_pgpkey(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        with pytest.raises(TypeError):
            kA.merge('not a key')

    def test_merge_requires_same_fingerprint(self, alice, bob):
        kA, _ = PGPKey.from_blob(alice.blobA)
        with pytest.raises(ValueError):
            kA.merge(bob.pubkey)

    def test_merge_requires_public(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        with pytest.raises(ValueError):
            alice.priv.merge(kA)
        with pytest.raises(ValueError):
            kA.merge(alice.priv)

    def test_merge_unions_packets(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        kB, _ = PGPKey.from_blob(alice.blobB)

        assert kA.merge(kB) is kA

        # the union of both copies' material
        assert {u.email for u in kA.userids} == {alice.email1, alice.email2}
        assert set(kA.subkeys) == {alice.sub1fp.keyid, alice.sub2fp.keyid}

        # revocation material from the later copy made it over
        sk1 = kA.subkeys[alice.sub1fp.keyid]
        assert len(list(sk1.revocation_signatures)) == 1
        uid1 = get_uid(kA, alice.email1)
        assert any(s.type == SignatureType.CertRevocation for s in uid1._signatures)

    def test_merge_is_idempotent(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        kB, _ = PGPKey.from_blob(alice.blobB)
        kA.merge(kB)
        before = inventory(kA)

        kA.merge(kB)
        kA.merge(kB)
        assert inventory(kA) == before

    def test_merge_does_not_modify_source(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        kB, _ = PGPKey.from_blob(alice.blobB)
        before = inventory(kB)

        kA.merge(kB)
        assert inventory(kB) == before

    def test_merge_keeps_distinct_signatures_with_same_issuer_and_created(self, alice, bob, bob_certs):
        cert1, cert2 = bob_certs
        # same issuer, same creation time, but different bytes
        assert cert1.signer == cert2.signer == bob.fingerprint.keyid
        assert cert1.created == cert2.created
        assert bytes(cert1) != bytes(cert2)

        kA, _ = PGPKey.from_blob(alice.blobA)
        uidA = get_uid(kA, alice.email1)
        uidA |= cert1
        kB, _ = PGPKey.from_blob(alice.blobB)
        uidB = get_uid(kB, alice.email1)
        uidB |= cert2

        kA.merge(kB)
        certs = {bytes(s) for s in get_uid(kA, alice.email1)._signatures
                 if s.signer == bob.fingerprint.keyid}
        assert certs == {bytes(cert1), bytes(cert2)}


class TestPGPKeyringMerge(object):
    def test_merge_combines_copies(self, alice):
        kr = PGPKeyring()
        loaded = kr.load(alice.blobA, alice.blobB, merge=True)

        # the return value names every key that was loaded, as with a plain load
        assert set(loaded) == {alice.fp, alice.sub1fp, alice.sub2fp}
        assert all(isinstance(f, Fingerprint) for f in loaded)

        # one merged view for the primary fingerprint, holding the union of both copies
        views = [k for k in kr._keys.values()
                 if k.is_primary and k.is_public and k.fingerprint == alice.fp]
        assert len(views) == 1
        merged = views[0]
        assert {u.email for u in merged.userids} == {alice.email1, alice.email2}
        assert set(merged.subkeys) == {alice.sub1fp.keyid, alice.sub2fp.keyid}
        assert len(list(merged.subkeys[alice.sub1fp.keyid].revocation_signatures)) == 1
        assert any(s.type == SignatureType.CertRevocation
                   for s in get_uid(merged, alice.email1)._signatures)

    def test_merge_order_independent(self, alice):
        kr1 = PGPKeyring()
        kr1.load(alice.blobA, alice.blobB, merge=True)
        kr2 = PGPKeyring()
        kr2.load(alice.blobB, alice.blobA, merge=True)

        with kr1.key(alice.fp) as m1, kr2.key(alice.fp) as m2:
            assert inventory(m1) == inventory(m2)

    def test_merge_repeated_imports_do_not_proliferate(self, alice):
        kr = PGPKeyring()
        kr.load(alice.blobA, alice.blobB, merge=True)
        with kr.key(alice.fp) as merged:
            before = inventory(merged)
            size = len(kr)

            kr.load(alice.blobB, merge=True)
            kr.load(alice.blobA, alice.blobB, merge=True)
            kr.load([alice.blobA, alice.blobA], merge=True)

            assert inventory(merged) == before
            assert len(kr) == size
            assert len(kr._pubkeys) == 1

    def test_merge_lookups_land_on_merged_view(self, alice, bob):
        kr = PGPKeyring()
        kr.load(bob.pubkey)
        kr.load(alice.blobA, merge=True)
        # a later, separate incremental import
        kr.load(alice.blobB, merge=True)

        # query by full primary fingerprint
        with kr.key(alice.fp) as merged:
            assert merged.is_public and merged.is_primary

        # query by the email of a UID that only exists in the later copy
        with kr.key(alice.email2) as byuid:
            assert byuid is merged

        # query by full subkey fingerprint: the subkey belongs to the merged primary
        with kr.key(alice.sub2fp) as sub2:
            assert sub2.parent is merged
        with kr.key(alice.sub1fp) as sub1:
            assert sub1.parent is merged

        # other primary keys are still looked up as before
        with kr.key(bob.fingerprint) as other:
            assert other.userids[0].email == 'bob@example.com'
        with kr.key('bob@example.com') as other:
            assert other.fingerprint == bob.fingerprint

        # fingerprints() sees the merged material exactly once
        fps = kr.fingerprints()
        assert {alice.fp, alice.sub1fp, alice.sub2fp, bob.fingerprint} <= fps
        assert kr.fingerprints(keytype='primary', keyhalf='public') == {alice.fp, bob.fingerprint}
        assert {alice.sub1fp, alice.sub2fp} <= kr.fingerprints(keytype='sub')

    def test_merge_roundtrip_through_bytes(self, alice):
        kr = PGPKeyring()
        kr.load(alice.blobA, alice.blobB, merge=True)
        with kr.key(alice.fp) as merged:
            reparsed, _ = PGPKey.from_blob(bytes(merged))

        # packet contents and ownership are preserved, including revocation signatures
        assert inventory(reparsed) == inventory(merged)
        sk1 = reparsed.subkeys[alice.sub1fp.keyid]
        assert len(list(sk1.revocation_signatures)) == 1
        assert any(s.type == SignatureType.CertRevocation
                   for s in get_uid(reparsed, alice.email1)._signatures)

    def test_merge_rejects_private_key_object(self, alice):
        kr = PGPKeyring()
        kr.load(alice.blobA, merge=True)
        before = keyring_snapshot(kr)

        with pytest.raises(ValueError):
            kr.load(alice.priv, merge=True)

        assert keyring_snapshot(kr) == before
        # the merged view is still intact and findable
        with kr.key(alice.fp) as merged:
            assert merged.is_public

    def test_merge_rejects_private_key_blob(self, alice):
        kr = PGPKeyring()
        # a private key hiding behind a valid public one rejects the whole call
        with pytest.raises(ValueError):
            kr.load(alice.blobA, alice.privblob, merge=True)

        assert len(kr) == 0
        assert kr.fingerprints() == set()
        assert alice.fp not in kr

    def test_merge_rejects_unparseable_input(self, alice):
        kr = PGPKeyring()
        kr.load(alice.blobA, merge=True)
        before = keyring_snapshot(kr)

        # garbage anywhere in the call rejects the whole call
        with pytest.raises(ValueError):
            kr.load(alice.blobB, b'this is not a key', merge=True)
        with pytest.raises(ValueError):
            kr.load(b'also not a key', alice.blobB, merge=True)

        assert keyring_snapshot(kr) == before

    def test_merge_does_not_mutate_caller_keys(self, alice):
        kA, _ = PGPKey.from_blob(alice.blobA)
        kB, _ = PGPKey.from_blob(alice.blobB)
        invA, invB = inventory(kA), inventory(kB)
        bytesA, bytesB = bytes(kA), bytes(kB)

        kr = PGPKeyring()
        kr.load(kA, kB, merge=True)

        # the caller-owned objects were not modified by the merge
        assert inventory(kA) == invA
        assert inventory(kB) == invB
        assert bytes(kA) == bytesA
        assert bytes(kB) == bytesB

        # the keyring holds its own merged view, not one of the caller's objects
        with kr.key(alice.fp) as merged:
            assert merged is not kA
            assert merged is not kB
            assert {u.email for u in merged.userids} == {alice.email1, alice.email2}

    def test_merge_absorbs_previously_loaded_copies(self, alice):
        kr = PGPKeyring()
        # an earlier copy loaded the old way
        kr.load(alice.blobA)
        assert len(kr._pubkeys) == 1

        kr.load(alice.blobB, merge=True)

        # the old copy was absorbed: exactly one public view of this primary remains
        views = [k for k in kr._keys.values()
                 if k.is_primary and k.is_public and k.fingerprint == alice.fp]
        assert len(views) == 1
        assert len(kr._pubkeys) == 1

        # material from both copies is there, and old and new aliases find the same view
        with kr.key(alice.fp) as merged:
            assert merged is views[0]
            assert {u.email for u in merged.userids} == {alice.email1, alice.email2}
        with kr.key(alice.email1) as k1, kr.key(alice.email2) as k2:
            assert k1 is k2 is views[0]

    def test_merge_coexists_with_private_half(self, alice):
        # the private half, as exported earlier on, only carries the first UID and subkey;
        # load it from its exported blob so both halves carry the same (second-resolution)
        # creation time, as they would when loaded from files
        priv, _ = PGPKey.from_blob(alice.privblobA)
        kr = PGPKeyring()
        kr.load(priv)
        before_priv = inventory(priv)

        kr.load(alice.blobA, alice.blobB, merge=True)

        # the private half was not touched by the merge
        assert inventory(priv) == before_priv
        assert len(kr._privkeys) == 1
        assert len(kr._pubkeys) == 1

        # the fingerprint alias prefers the private half, as with any pub/priv pair
        with kr.key(alice.fp) as k:
            assert not k.is_public
        # material the private half does not have lands uniquely on the merged public view
        with kr.key(alice.email2) as k:
            assert k.is_public
            assert {u.email for u in k.userids} == {alice.email1, alice.email2}
        with kr.key(alice.sub2fp) as k:
            assert k.is_public
            assert k.parent.is_public and k.parent.is_primary

    def test_merge_unload_and_reimport(self, alice):
        kr = PGPKeyring()
        kr.load(alice.blobA, alice.blobB, merge=True)
        with kr.key(alice.fp) as merged:
            kr.unload(merged)

        assert alice.fp not in kr
        assert alice.email2 not in kr
        assert alice.sub1fp not in kr
        assert alice.sub2fp not in kr

        # re-importing after an unload rebuilds the view from scratch
        kr.load(alice.blobB, merge=True)
        with kr.key(alice.fp) as merged:
            assert {u.email for u in merged.userids} == {alice.email1, alice.email2}
            assert set(merged.subkeys) == {alice.sub1fp.keyid, alice.sub2fp.keyid}

    def test_merge_multiple_primaries_one_call(self, alice, bob):
        kr = PGPKeyring()
        loaded = kr.load([alice.blobA, bytes(bob.pubkey)], merge=True)

        assert set(loaded) == {alice.fp, alice.sub1fp, bob.fingerprint}
        with kr.key(bob.fingerprint) as k:
            assert k.userids[0].email == 'bob@example.com'
        with kr.key(alice.fp) as k:
            assert {u.email for u in k.userids} == {alice.email1}

    def test_merge_distinct_signatures_with_same_issuer_and_created(self, alice, bob, bob_certs):
        cert1, cert2 = bob_certs
        kA, _ = PGPKey.from_blob(alice.blobA)
        uidA = get_uid(kA, alice.email1)
        uidA |= cert1
        kB, _ = PGPKey.from_blob(alice.blobB)
        uidB = get_uid(kB, alice.email1)
        uidB |= cert2

        kr = PGPKeyring()
        kr.load(bytes(kA), bytes(kB), merge=True)

        with kr.key(alice.fp) as merged:
            certs = {bytes(s) for s in get_uid(merged, alice.email1)._signatures
                     if s.signer == bob.fingerprint.keyid}
            assert certs == {bytes(cert1), bytes(cert2)}

    def test_merge_empty_call(self):
        kr = PGPKeyring()
        assert kr.load(merge=True) == []
        assert len(kr) == 0

    def test_load_without_merge_keeps_historical_behavior(self, alice):
        # without merge=True, every loaded copy is stored as-is, duplicates included
        kr = PGPKeyring()
        kr.load(alice.blobA, alice.blobA)
        kr.load(alice.blobB)

        views = [k for k in kr._keys.values()
                 if k.is_primary and k.is_public and k.fingerprint == alice.fp]
        assert len(views) == 3
        assert len(kr._pubkeys) == 3

    def test_merge_repo_fixture_idempotent(self):
        with open('tests/testdata/blocks/rsapubkey.asc', 'rb') as f:
            blob = f.read()

        kr = PGPKeyring()
        kr.load(blob, merge=True)
        with kr.key('F4294BC8094A7E0585C85E8637473B3758C44F36') as merged:
            before = inventory(merged)

        kr.load(blob, blob, merge=True)
        with kr.key('F4294BC8094A7E0585C85E8637473B3758C44F36') as merged:
            assert inventory(merged) == before
        assert len(kr._pubkeys) == 1
