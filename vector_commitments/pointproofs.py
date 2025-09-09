import math
from charm.toolbox.pairinggroup import ZR, G1, G2, GT, pair

from util.util import group

"""
PointProofs vector commitment with point proofs and aggregation.
Reference: Lai, Malavolta, Schröder, Thyagarajan, "Pointproofs: Aggregating Proofs for Multiple Vector Commitments," CCS 2020.
"""

class SK:
    """Secret key for PointProofs: powers of alpha up to 2N-1."""
    def __init__(self, sk):
        self.sk = sk


class PK:
    """Public parameters for PointProofs (generators and key elements)."""
    def __init__(self, g1, g2, pk_g1, pk_g2, pk_gt):
        self.g1 = g1
        self.g2 = g2
        self.pk_g1 = pk_g1
        self.pk_g2 = pk_g2
        self.pk_gt = pk_gt


def generate_keys(N: int) -> tuple[SK, PK]:
    """Generate PointProofs keys for vector length N.

    Returns secret powers and public elements in G1/G2/GT.
    """
    g1 = group.random(G1)
    g2 = group.random(G2)
    alpha = group.random(ZR)

    sk = [(alpha**i) for i in range(1, 2 * N + 1)]
    pk_g1 = [(g1**alpha) for idx, alpha in enumerate(sk) if idx is not N + 1]
    pk_g2 = [(g2**alpha) for alpha in sk[:N]]
    pk_gt = pair(g1, g2) ** sk[N]

    return SK(sk), PK(g1, g2, pk_g1, pk_g2, pk_gt)


def commit(g1: G1, messages: list[ZR], sk: list[ZR]) -> G1:
    """Commit to a vector of messages using powers of alpha in G1."""
    return g1 ** (
        sum(message * alpha for message, alpha in zip(messages, sk[: len(messages)]))
    )


def update_commit(
    g1: G1,
    v_commit: G1,
    sk: list[ZR],
    idxs: list[int],
    messages: list[ZR],
    new_messages: list[ZR],
) -> G1:
    """Update commitment in place given index-value changes (no recompute)."""
    return v_commit * (
        g1
        ** sum(
            (new_message - message) * sk[idx]
            for new_message, message, idx in zip(new_messages, messages, idxs)
        )
    )


def generate_proof(
    pk_g1: list[G1], sk: list[ZR], v_commit: G1, index: int, message: ZR
) -> G1:
    """Generate a point proof for value at position index."""
    return (v_commit / (pk_g1[index] ** message)) ** sk[
        int((len(pk_g1) + 1) / 2) - (index + 1)
    ]


def verify_proof(
    g2: G2,
    pk_g2: list[G2],
    pk_gt: GT,
    v_commit: G1,
    message: ZR,
    index: int,
    proof_i: G1,
) -> bool:
    """Verify a single point proof for the committed vector at index."""
    return pair(v_commit, pk_g2[len(pk_g2) - (index + 1)]) == pair(proof_i, g2) * (
        pk_gt**message
    )


def compute_t(
    v_commit: G1, messages: list[ZR], indexes: list[int]
) -> list[ZR]:
    """Compute Fiat-Shamir scalars for aggregation over given indexes."""
    return [
        group.hash(
            group.serialize(group.init(ZR, i))
            + group.serialize(v_commit)
            + group.serialize(message)
        )
        for i, message in zip(indexes, messages)
    ]


def aggregate_proofs(
    v_commit: G1, messages: list[ZR], indexes: list[int], proofs: list[G1]
) -> G1:
    """Aggregate single proofs into one using Fiat-Shamir scalars t."""
    t = compute_t(v_commit, messages, indexes)
    return math.prod(proof_i**t_i for proof_i, t_i in zip(proofs, t))


def verify_aggregate_proofs(
    g2: G2,
    pk_g2: list[G2],
    pk_gt: GT,
    v_commit: G1,
    messages: list[ZR],
    indexes: list[int],
    aggregate_proofs: G1,
) -> bool:
    """Verify an aggregated proof for a set of positions indexes."""
    t = compute_t(v_commit, messages, indexes)

    return pair(
        v_commit,
        math.prod(pk_g2[len(pk_g2) - (i + 1)] ** t_i for i, t_i in zip(indexes, t)),
    ) == pair(aggregate_proofs, g2) * (
        pk_gt ** sum(message * t_i for message, t_i in zip(messages, t))
    )


if __name__ == "__main__":
    N = 4
    messages = [group.random(ZR) for _ in range(N)]

    sk, pk = generate_keys(len(messages))

    v_commit = commit(pk.g1, messages, sk.sk)

    i = 1
    proof_i_1 = generate_proof(pk.pk_g1, sk.sk, v_commit, i, messages[i])
    check = verify_proof(pk.g2, pk.pk_g2, pk.pk_gt, v_commit, messages[i], i, proof_i_1)
    assert check

    new_messages = [group.random(ZR) for _ in range(2)]
    idxs_to_update = [1, 2]
    v_commit = update_commit(
        pk.g1, v_commit, sk.sk, idxs_to_update, messages, new_messages
    )
    messages = [messages[0], new_messages[0], new_messages[1], messages[3]]

    i = 1
    proof_i_1 = generate_proof(pk.pk_g1, sk.sk, v_commit, i, messages[i])
    check = verify_proof(pk.g2, pk.pk_g2, pk.pk_gt, v_commit, messages[i], i, proof_i_1)
    assert check

    i = 3
    proof_i_2 = generate_proof(pk.pk_g1, sk.sk, v_commit, i, messages[i])
    check = verify_proof(pk.g2, pk.pk_g2, pk.pk_gt, v_commit, messages[i], i, proof_i_2)
    assert check

    aggregate_proofs = aggregate_proofs(
        v_commit, [messages[1], messages[3]], [1, 3], [proof_i_1, proof_i_2]
    )

    check = verify_aggregate_proofs(
        pk.g2,
        pk.pk_g2,
        pk.pk_gt,
        v_commit,
        [messages[1], messages[3]],
        [1, 3],
        aggregate_proofs,
    )
    assert check
