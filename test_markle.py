import pytest
from merkle_lib import merkle_tree_hash, tagged_hash, serialize_user, hash_leaf
import binascii

def test_merkle_root():
    data = ["aaa", "bbb", "ccc", "ddd", "eee"]
    expected_length = 32  # SHA256 output length in bytes
    root = merkle_tree_hash(data, "Bitcoin_Transaction")
    assert isinstance(root, bytes)
    assert len(root) == expected_length

def test_tagged_hash():
    tag = "TestTag"
    msg = b"hello"
    h = tagged_hash(tag, msg)
    assert isinstance(h, bytes)
    assert len(h) == 32  # SHA256

def test_leaf_hash_consistency():
    user = (10, 100)
    serialized = serialize_user(user)
    hashed = hash_leaf("ProofOfReserve_Leaf", serialized)
    assert binascii.hexlify(hashed).decode()  # Should be valid hex
