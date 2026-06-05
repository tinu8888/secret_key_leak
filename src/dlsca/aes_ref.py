"""Reference AES-128 decryption (and an encrypt cross-check), pure NumPy, no hardware.

Used by the masking test suite to prove the *original data is recoverable*:
decrypting a ciphertext produced by the (masked or unprotected) AES must return the exact
plaintext. Encryption already lives in :mod:`dlsca.dataset`; this module adds the inverse so a
full round trip can be asserted. Verified against the FIPS-197 test vector in ``__main__`` and
in ``tests/``.
"""
from __future__ import annotations

import numpy as np

from .dataset import _key_expansion, aes128_encrypt_block
from .leakage import sbox as _fwd_sbox

# Inverse AES S-box (standard FIPS-197 table).
INV_SBOX = np.array([
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
], dtype=np.uint8)


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8) with the AES reduction polynomial 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = int(INV_SBOX[state[i]])


def _inv_shift_rows(state):
    # Inverse of ShiftRows: rotate each row right by its row index.
    s = state[:]
    # row 1 right by 1
    state[1], state[5], state[9], state[13] = s[13], s[1], s[5], s[9]
    # row 2 right by 2
    state[2], state[6], state[10], state[14] = s[10], s[14], s[2], s[6]
    # row 3 right by 3
    state[3], state[7], state[11], state[15] = s[7], s[11], s[15], s[3]


def _inv_mix_columns(state):
    for c in range(4):
        col = state[c * 4:c * 4 + 4]
        a0, a1, a2, a3 = col
        state[c * 4 + 0] = _gmul(a0, 14) ^ _gmul(a1, 11) ^ _gmul(a2, 13) ^ _gmul(a3, 9)
        state[c * 4 + 1] = _gmul(a0, 9) ^ _gmul(a1, 14) ^ _gmul(a2, 11) ^ _gmul(a3, 13)
        state[c * 4 + 2] = _gmul(a0, 13) ^ _gmul(a1, 9) ^ _gmul(a2, 14) ^ _gmul(a3, 11)
        state[c * 4 + 3] = _gmul(a0, 11) ^ _gmul(a1, 13) ^ _gmul(a2, 9) ^ _gmul(a3, 14)


def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= int(rk[i])


def aes128_decrypt_block(ciphertext16, key16) -> np.ndarray:
    """Decrypt one 16-byte AES-128 block (ECB). Inverse of ``dataset.aes128_encrypt_block``.

    Returns:
        ``uint8`` array of 16 plaintext bytes.
    """
    ct = np.asarray(ciphertext16, dtype=np.uint8).reshape(16)
    key = np.asarray(key16, dtype=np.uint8).reshape(16)
    round_keys = _key_expansion(key)
    state = [int(b) for b in ct]

    _add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])
    return np.array(state, dtype=np.uint8)


def aes128_decrypt(ciphertexts: np.ndarray, keys: np.ndarray) -> np.ndarray:
    """Vectorized decrypt over ``(N, 16)`` ciphertexts/keys."""
    cts = np.asarray(ciphertexts, dtype=np.uint8).reshape(-1, 16)
    ks = np.asarray(keys, dtype=np.uint8).reshape(-1, 16)
    if cts.shape[0] != ks.shape[0]:
        raise ValueError("ciphertexts and keys must have the same N")
    out = np.empty_like(cts)
    for i in range(cts.shape[0]):
        out[i] = aes128_decrypt_block(cts[i], ks[i])
    return out


if __name__ == "__main__":
    # FIPS-197 known-answer round trip.
    key = np.arange(16, dtype=np.uint8)
    pt = np.frombuffer(bytes.fromhex("00112233445566778899aabbccddeeff"), dtype=np.uint8)
    ct = aes128_encrypt_block(pt, key)
    back = aes128_decrypt_block(ct, key)
    assert bytes(ct.tolist()).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a", ct
    assert np.array_equal(back, pt), back
    # INV_SBOX must invert the forward S-box.
    assert all(int(INV_SBOX[int(_fwd_sbox(np.array([x]))[0])]) == x for x in range(256))
    print("aes_ref OK: encrypt+decrypt round trip and inverse S-box verified (FIPS-197).")
