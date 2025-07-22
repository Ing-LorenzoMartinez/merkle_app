import hashlib
import math

def serialize_user(user):
    return f"({user[0]},{user[1]})"

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode('utf-8')).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def serialize_leaf(data: str) -> bytes:
    return data.encode('utf-8')

def hash_leaf(tag: str, data: str) -> bytes:
    return tagged_hash(tag, serialize_leaf(data))

def merkle_tree_hash(data_list: list[str], tag: str) -> bytes:
    hashes = [hash_leaf(tag, d) for d in data_list]

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # Duplicar último si impar

        new_level = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i+1]
            new_hash = tagged_hash(tag, combined)
            new_level.append(new_hash)
        hashes = new_level

    return hashes[0]
