"""Real PGP keys and message helpers shared by the tests."""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import (
    CompressionAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm,
)

# PGPy/cryptography deprecation noise would bury the test output.
warnings.filterwarnings("ignore")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

PASSPHRASE = "correct horse"


def new_key(name: str, protect: bool = False) -> PGPKey:
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
    key.add_uid(
        PGPUID.new(name, email=f"{name.lower()}@example.test"),
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256],
        ciphers=[SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.Uncompressed],
    )
    if protect:
        key.protect(PASSPHRASE, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
    return key


def encrypt_for(key: PGPKey, text: str) -> str:
    return str(key.pubkey.encrypt(PGPMessage.new(text)))


def decrypt_with(key: PGPKey, armored: str) -> str:
    msg = PGPMessage.from_blob(armored)
    if key.is_protected:
        with key.unlock(PASSPHRASE):
            out = key.decrypt(msg).message
    else:
        out = key.decrypt(msg).message
    return out.decode() if isinstance(out, (bytes, bytearray)) else str(out)
