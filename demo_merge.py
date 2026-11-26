#!/usr/bin/env python3
"""Terminal demo: incremental public-key import with PGPKeyring.load(merge=True).

Generates a test key in-process (no GnuPG, no network), exports two partial public
copies of it at different points in its life, and shows that merging them into one
keyring produces a single view with the union of their packets, reachable through
the keyring's usual lookups.

Run with the repository as the working directory:

    python3 demo_merge.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pgpy import PGPKey  # noqa: E402
from pgpy import PGPKeyring  # noqa: E402
from pgpy import PGPUID  # noqa: E402
from pgpy.constants import HashAlgorithm  # noqa: E402
from pgpy.constants import KeyFlags  # noqa: E402
from pgpy.constants import PubKeyAlgorithm  # noqa: E402
from pgpy.constants import RevocationReason  # noqa: E402
from pgpy.constants import SignatureType  # noqa: E402

CHECKS = []


def check(label, ok):
    CHECKS.append(ok)
    print('    [{:s}] {:s}'.format('PASS' if ok else 'FAIL', label))


def inventory(key):
    """Order-insensitive inventory of a key's packets, grouped by owner."""
    return {
        'primary': bytes(key._key),
        'sigs': sorted(bytes(s) for s in key._signatures if not s.embedded),
        'uids': {bytes(u._uid): sorted(bytes(s) for s in u._signatures) for u in key._uids},
        'subkeys': {sk.fingerprint: (bytes(sk._key),
                                     sorted(bytes(s) for s in sk._signatures if not s.embedded))
                    for sk in key.subkeys.values()},
    }


def describe(key):
    lines = ['primary 0x{:s} ({:d} key-level signature(s))'
             ''.format(key.fingerprint.keyid, len([s for s in key._signatures if not s.embedded]))]
    for uid in key.userids:
        kinds = ', '.join(sorted(s.type.name for s in uid._signatures)) or '-'
        lines.append('  UID  {:s} <{:s}>  sigs: {:s}'.format(uid.name, uid.email, kinds))
    for skid, sk in key.subkeys.items():
        kinds = ', '.join(sorted(s.type.name for s in sk._signatures if not s.embedded)) or '-'
        lines.append('  SUB  0x{:s}  sigs: {:s}'.format(skid, kinds))
    return '\n'.join(lines)


def main():
    print('=== PGPKeyring.load(merge=True) demo ===')
    print('(key generated in-process; no GnuPG, no network)\n')

    print('1. Generate a key and take two partial public exports of it')
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    uid1 = PGPUID.new('Alice Aardvark', email='alice@example.com')
    key.add_uid(uid1, usage={KeyFlags.Certify, KeyFlags.Sign}, hashes=[HashAlgorithm.SHA256])
    sub1 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub1, usage={KeyFlags.EncryptCommunications})
    blob_a = bytes(key.pubkey)          # earlier export: uid1 + sub1

    uid2 = PGPUID.new('Alice A', email='alice.a@example.com')
    key.add_uid(uid2, usage={KeyFlags.Certify}, hashes=[HashAlgorithm.SHA256])
    sub2 = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub2, usage={KeyFlags.EncryptCommunications})
    sub1 |= key.revoke(sub1, reason=RevocationReason.Retired, comment='superseded')
    uid1 |= key.revoke(uid1)
    blob_b = bytes(key.pubkey)          # later export: + uid2, sub2, and two revocations

    copy_a, _ = PGPKey.from_blob(blob_a)
    copy_b, _ = PGPKey.from_blob(blob_b)
    print('   copy A (earlier export):\n    ' + describe(copy_a).replace('\n', '\n    '))
    print('   copy B (later export):\n    ' + describe(copy_b).replace('\n', '\n    '))
    check('both copies are the same primary key', copy_a.fingerprint == copy_b.fingerprint)

    print('\n2. Load both copies into one keyring with merge=True')
    keyring = PGPKeyring()
    loaded = keyring.load(blob_a, blob_b, merge=True)
    print('    loaded fingerprints: {:d}'.format(len(loaded)))
    with keyring.key(key.fingerprint) as merged:
        print('   merged view:\n    ' + describe(merged).replace('\n', '\n    '))
        inv_merged = inventory(merged)
        check('merged view holds the union of both copies',
              inv_merged['uids'].keys() == inventory(copy_a)['uids'].keys() | inventory(copy_b)['uids'].keys()
              and inv_merged['subkeys'].keys() == inventory(copy_a)['subkeys'].keys() | inventory(copy_b)['subkeys'].keys())
        check('subkey revocation from copy B is present',
              any(s.type == SignatureType.SubkeyRevocation
                  for s in merged.subkeys[sub1.fingerprint.keyid]._signatures))
        check('UID certification revocation from copy B is present',
              any(s.type == SignatureType.CertRevocation for s in merged.userids[0]._signatures)
              or any(s.type == SignatureType.CertRevocation for s in merged.userids[1]._signatures))
        check('exactly one public primary for this fingerprint in the keyring',
              len([k for k in keyring._keys.values()
                   if k.is_primary and k.is_public and k.fingerprint == key.fingerprint]) == 1)

        print('\n3. Lookups land on the merged view')
        with keyring.key('alice.a@example.com') as by_email:
            check('new UID email -> merged view', by_email is merged)
        with keyring.key(str(key.fingerprint)) as by_fp:
            check('full primary fingerprint -> merged view', by_fp is merged)
        with keyring.key(sub2.fingerprint) as by_sub:
            check('full subkey fingerprint -> subkey of merged view', by_sub.parent is merged)
        check('fingerprints() lists primary and both subkeys',
              {key.fingerprint, sub1.fingerprint, sub2.fingerprint} <= keyring.fingerprints())

        print('\n4. Order and repetition do not matter')
        keyring2 = PGPKeyring()
        keyring2.load(blob_b, blob_a, merge=True)
        with keyring2.key(key.fingerprint) as merged2:
            check('load(B, A) has the same packet set as load(A, B)', inventory(merged2) == inv_merged)
        before = inv_merged
        keyring.load(blob_a, blob_b, merge=True)
        keyring.load(blob_b, merge=True)
        check('re-importing the same copies changes nothing', inventory(merged) == before)
        check('keyring still holds exactly one public copy', len(keyring._pubkeys) == 1)

        print('\n5. Export the merged view and read it back')
        reparsed, _ = PGPKey.from_blob(bytes(merged))
        check('PGPKey.from_blob(bytes(merged)) preserves every packet',
              inventory(reparsed) == inv_merged)
        check('revocation signatures survive the round trip',
              any(s.type == SignatureType.SubkeyRevocation
                  for s in reparsed.subkeys[sub1.fingerprint.keyid]._signatures))

    print('\n6. A failing call is rejected as a whole')
    before = (len(keyring), set(keyring.fingerprints()))
    try:
        keyring.load(blob_a, b'this is not a key', merge=True)
        check('unparseable input rejected', False)
    except ValueError as e:
        check('unparseable input rejected ({:s})'.format(str(e)), True)
    try:
        keyring.load(blob_a, bytes(key), merge=True)   # private key material
        check('private key material rejected', False)
    except ValueError as e:
        check('private key material rejected ({:s})'.format(str(e)), True)
    check('keyring contents unchanged after rejected calls',
          (len(keyring), set(keyring.fingerprints())) == before)

    print('\n7. Caller-owned key objects are never modified')
    caller_copy, _ = PGPKey.from_blob(blob_a)
    snapshot = bytes(caller_copy)
    PGPKeyring().load(caller_copy, blob_b, merge=True)
    check('the PGPKey passed to load is byte-for-byte unchanged', bytes(caller_copy) == snapshot)

    print('\n{:s}'.format('ALL CHECKS PASSED' if all(CHECKS) else 'SOME CHECKS FAILED'))
    return 0 if all(CHECKS) else 1


if __name__ == '__main__':
    sys.exit(main())
