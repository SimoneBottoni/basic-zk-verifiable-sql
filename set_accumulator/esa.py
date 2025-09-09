import random

from charm.toolbox.pairinggroup import ZR, G1, G2, pair

from util.util import group, MAXINT

"""
ESA: An expressive zero-knowledge set accumulator and simple aggregation proofs.
Reference: Camenisch, Kohlweiss, Rial, "An Expressive (Zero-Knowledge) Set Accumulator," PKC 2009.
"""

class SK:
    """Secret key wrapper for the ESA accumulator and aggregation proofs."""
    def __init__(self, sk):
        self.sk = sk


class PK:
    """Public parameters for ESA aggregation proofs.

    Contains generators and per-aggregation verification keys.
    """
    def __init__(
        self, g1: G1, g2: G2, pk_count: G1, pk_sum: G1, pk_min: G1, pk_min_2: G1
    ):
        self.g1 = g1
        self.g2 = g2
        self.pk_count = pk_count
        self.pk_sum = pk_sum
        self.pk_min = pk_min
        self.pk_min_2 = pk_min_2


def generate_keys(min: ZR) -> tuple[SK, PK]:
    """Sample keys and verification parameters given the minimum domain value.

    The min parameter seeds the MIN proof verification keys.
    """
    g1 = group.random(G1)
    g2 = group.random(G2)
    sk = group.random(ZR)

    pk_count = g1 ** (sk - group.init(ZR, 1))
    pk_sum = g1 ** ((sk - group.init(ZR, 1)) ** 2)
    pk_min = g1 ** (sk**min)
    pk_min_2 = g1 ** (sk ** (min + group.init(ZR, 1)))

    return SK(sk), PK(g1, g2, pk_count, pk_sum, pk_min, pk_min_2)


def compute_accumulator(sk: ZR, dataset: list[ZR]) -> ZR:
    """Compute polynomial accumulator A(sk) = Σ sk^i for i in dataset."""
    return sum([sk**i for i in dataset])


def generate_count_proof(
    g2: G2, sk: ZR, acc: ZR, dataset: list[ZR]
) -> tuple[G2, ZR]:
    """Prove COUNT over the set equals acc evaluated at 1.

    Returns (proof, count_value=acc(1)).
    """
    acc_1 = compute_accumulator(1, dataset)
    proof = g2 ** ((acc - acc_1) / (sk - 1))
    return proof, acc_1


def verify_count_proof(
    g1: G1, g2: G2, pk_count: G1, acc: ZR, proof: G2, count: ZR
) -> bool:
    """Check e(g1^acc / g1^count, g2) == e(pk_count, proof)."""
    p1 = pair(g1**acc / g1**count, g2)
    p2 = pair(pk_count, proof)
    return p1 == p2


def generate_sum_proof(
    g2: G2, sk: ZR, acc: ZR, dataset: list[ZR]
) -> tuple[G2, ZR, ZR]:
    """Prove SUM over the set by evaluating derivatives at 1.

    Returns (proof_1, proof_2=acc(1), sum_value=acc'(1)).
    """
    acc_1 = compute_accumulator(1, dataset)
    acc_1d = sum([i * sk ** (i - 1) for i in dataset])
    b_x = (acc - acc_1 - acc_1d * (sk - group.init(ZR, 1))) / (
        (sk - group.init(ZR, 1)) ** 2
    )
    proof_1 = g2**b_x
    proof_2 = acc_1
    return proof_1, proof_2, acc_1d


def verify_sum_proof(
    g1: G1, g2: G2, pk_sum: G1, pk_count: G1, acc: ZR, proof_1: G2, proof_2: ZR, sum: ZR
) -> bool:
    """Check e(g1^acc, g2) == e(pk_sum, proof_1) * e(pk_count^sum * g1^{acc(1)}, g2)."""
    p1 = pair(g1**acc, g2)
    p2 = pair(pk_sum, proof_1) * pair((pk_count**sum) * (g1**proof_2), g2)
    return p1 == p2


def generate_min_proof(g2: G2, sk: ZR, acc: ZR, min: ZR) -> tuple[G2, ZR]:
    """Prove MIN equals the provided min by showing (acc - sk^min)/(sk^{min+1})."""
    proof = g2 ** ((acc - sk**min) / sk ** (min + group.init(ZR, 1)))
    return proof, min


def verify_min_proof(
    g1: G1, g2: G2, pk_min: G1, pk_min_2: G1, acc: ZR, proof: G2
) -> bool:
    """Check e(g1^acc, g2) == e(pk_min, g2) * e(proof, pk_min_2)."""
    p1 = pair(g1**acc, g2)
    p2 = pair(pk_min, g2) * pair(proof, pk_min_2)
    return p1 == p2


if __name__ == "__main__":
    N = 4
    dataset = [random.randint(1, MAXINT) for _ in range(N)]
    min_value = min(dataset)
    dataset = [group.init(ZR, el) for el in dataset]

    sk, pk = generate_keys(min_value)

    acc = compute_accumulator(sk.sk, dataset)

    proof, count = generate_count_proof(pk.g2, sk.sk, acc, dataset)
    check = verify_count_proof(pk.g1, pk.g2, pk.pk_count, acc, proof, count)
    assert check

    proof_1, proof_2, sum = generate_sum_proof(pk.g2, sk.sk, acc, dataset)
    check = verify_sum_proof(
        pk.g1, pk.g2, pk.pk_sum, pk.pk_count, acc, proof_1, proof_2, sum
    )
    assert check

    proof, _ = generate_min_proof(pk.g2, sk.sk, acc, min_value)
    check = verify_min_proof(pk.g1, pk.g2, pk.pk_min, pk.pk_min_2, acc, proof)
    assert check
