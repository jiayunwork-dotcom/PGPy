#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terminal demonstration of the unlock lifetime fix.

Run (offline, no GnuPG required, all keys are generated in-process):

    python3 demo_unlock_lifetime.py

It prints, for each scenario, whether signing succeeds or is refused at every
stage. Exit status is 0 if every expectation holds, 1 otherwise.
"""
import copy
import sys
import warnings

from pgpy import PGPKey
from pgpy import PGPUID
from pgpy.constants import HashAlgorithm
from pgpy.constants import KeyFlags
from pgpy.constants import PubKeyAlgorithm
from pgpy.constants import SymmetricKeyAlgorithm
from pgpy.errors import PGPDecryptionError
from pgpy.errors import PGPError

warnings.simplefilter("ignore")

PASSPHRASE = "correct horse battery staple"
OK = "\033[32mSIGN OK\033[0m"
NO = "\033[31mSIGN REFUSED\033[0m"
ERR = "\033[33mRAISED %s\033[0m"


def make_key(protect=True, subkey_plaintext=False):
    uid = PGPUID.new("Lifetime Demo", email="demo@example.com")
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_uid(uid,
                usage={KeyFlags.Sign, KeyFlags.Certify},
                hashes=[HashAlgorithm.SHA256],
                ciphers=[SymmetricKeyAlgorithm.AES256])
    sub = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
    key.add_subkey(sub, usage={KeyFlags.Sign})

    if protect:
        if subkey_plaintext:
            # protect the primary packet only; the subkey stays unencrypted
            key._key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
        else:
            key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def sign_status(key, label):
    try:
        key.sign(b"demo payload")
        print("    {:42s} {}".format(label, OK))
        return True
    except PGPError:
        print("    {:42s} {}".format(label, NO))
        return False


def heading(text):
    print("\n=== {} ===".format(text))


def main():
    results = []

    # 1. ordinary single-layer unlock
    heading("1. single-layer unlock")
    key = make_key()
    results.append(("1 locked before scope", sign_status(key, "before unlock") is False))
    with key.unlock(PASSPHRASE):
        results.append(("1 signing inside scope", sign_status(key, "inside unlock") is True))
    results.append(("1 locked after scope", sign_status(key, "after unlock exited") is False))

    # 2. nested scopes: inner exit and inner failure cannot end the outer scope
    heading("2. nested unlock: inner scope cannot kill outer scope")
    key = make_key()
    with key.unlock(PASSPHRASE):
        with key.unlock(PASSPHRASE):
            sign_status(key, "inner scope")
        results.append(("2 outer alive after inner exit", sign_status(key, "outer after inner exit") is True))

        other = make_key()
        try:
            with other.unlock("wrong passphrase"):
                pass
        except PGPDecryptionError as exc:
            print("    unrelated failed unlock: {}".format(ERR % type(exc).__name__))
        results.append(("2 outer alive after failed unlock", sign_status(key, "outer after failed unlock") is True))
    results.append(("2 locked after outer exit", sign_status(key, "after outer exit") is False))

    # 3. copy inside a scope shares the scope; nothing usable afterwards
    heading("3. copy inside an unlock scope")
    key = make_key()
    with key.unlock(PASSPHRASE):
        snapshot = copy.copy(key)
        sub_ref = next(iter(key.subkeys.values()))
        results.append(("3 copy signs inside scope", sign_status(snapshot, "copy inside scope") is True))
        results.append(("3 subkey ref signs inside scope", sign_status(sub_ref, "subkey ref inside scope") is True))
    results.append(("3 copy locked afterwards", sign_status(snapshot, "copy after scope exit") is False))
    results.append(("3 subkey ref locked afterwards", sign_status(sub_ref, "subkey ref after scope exit") is False))

    # 4. unencrypted subkey must never be wiped
    heading("4. unencrypted subkey is never wiped")
    key = make_key(subkey_plaintext=True)
    sub = next(iter(key.subkeys.values()))
    sign_status(sub, "subkey before primary unlock")
    with key.unlock(PASSPHRASE):
        sign_status(sub, "subkey during primary unlock")
    results.append(("4 subkey alive after exit", sign_status(sub, "subkey after unlock exit") is True))

    key = make_key(subkey_plaintext=True)
    sub = next(iter(key.subkeys.values()))
    try:
        with key.unlock("wrong passphrase"):
            pass
    except PGPDecryptionError as exc:
        print("    wrong-passphrase unlock: {}".format(ERR % type(exc).__name__))
    results.append(("4 subkey alive after failure", sign_status(sub, "subkey after failed unlock") is True))

    # 5. export stability and re-use
    heading("5. exported bytes are unchanged; re-import still works")
    key = make_key()
    before = bytes(key)
    with key.unlock(PASSPHRASE):
        key.sign(b"signed while unlocked")
        inside = bytes(key)
    after = bytes(key)
    same = before == inside == after
    print("    {:42s} {}".format("export identical before/during/after",
                                 "\033[32mYES\033[0m" if same else "\033[31mNO\033[0m"))
    results.append(("5 export bytes stable", same))

    reloaded = PGPKey()
    reloaded.parse(bytearray(after))
    with reloaded.unlock(PASSPHRASE):
        results.append(("5 reloaded key signs after re-unlock", sign_status(reloaded, "reloaded + re-unlocked") is True))
    results.append(("5 reloaded key locks again", sign_status(reloaded, "reloaded after exit") is False))

    print("\n--- summary ---")
    ok = True
    for name, passed in results:
        print("  [{:3s}] {}".format("PASS" if passed else "FAIL", name))
        ok = ok and passed
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
