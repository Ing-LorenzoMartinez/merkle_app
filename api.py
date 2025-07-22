from flask import Flask, jsonify
import binascii
from merkle_lib import tagged_hash, hash_leaf, merkle_tree_hash, serialize_user

app = Flask(__name__)
users = [(i, i*1111) for i in range(1, 9)]

#def serialize_user(user):
#    return f"({user[0]},{user[1]})"

def generate_merkle_proof(index, leaf_hashes, tag):
    proof = []
    idx = index
    level = leaf_hashes.copy()

    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])

        new_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i+1]
            new_hash = tagged_hash(tag, combined)
            new_level.append(new_hash)

            if i == idx or i+1 == idx:
                sibling = level[i+1] if idx == i else level[i]
                direction = 0 if idx % 2 == 1 else 1
                proof.append((binascii.hexlify(sibling).decode(), direction))

        idx = idx // 2
        level = new_level

    return proof

@app.route("/proof-root")
def proof_root():
    leaves = [serialize_user(u) for u in users]
    root = merkle_tree_hash(leaves, "ProofOfReserve_Leaf")
    return jsonify({"merkle_root": binascii.hexlify(root).decode()})

@app.route("/proof/<int:user_id>")
def proof(user_id):
    if not any(u[0] == user_id for u in users):
        return jsonify({"error": "User not found"}), 404

    leaves = [serialize_user(u) for u in users]
    leaf_hashes = [hash_leaf("ProofOfReserve_Leaf", l) for l in leaves]
    index = next(i for i, u in enumerate(users) if u[0] == user_id)
    proof_data = generate_merkle_proof(index, leaf_hashes, "ProofOfReserve_Branch")

    balance = next(u[1] for u in users if u[0] == user_id)
    return jsonify({
        "user_balance": balance,
        "merkle_proof": proof_data
    })

if __name__ == "__main__":
    app.run(debug=True)