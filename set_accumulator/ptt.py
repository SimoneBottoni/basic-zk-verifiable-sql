import math
from charm.toolbox.pairinggroup import ZR, G1, G2, pair

from util.util import group

"""
PTT set accumulator used for subset proofs.
Reference: Papamanthou, Shi, Tamassia, "Optimal Verification of Operations on Dynamic Sets," CRYPTO 2011.
"""

class SK:
    """Secret key wrapper for the PTT set accumulator."""
    def __init__(self, sk):
        self.sk = sk


class PK:
    """Public parameters for PTT: group generators in G1 and G2."""
    def __init__(self, g1, g2):
        self.g1 = g1
        self.g2 = g2


def generate_keys() -> tuple[SK, PK]:
    """Sample secret and public parameters for the PTT accumulator."""
    sk = group.random(ZR)
    g1 = group.random(G1)
    g2 = group.random(G2)
    return SK(sk), PK(g1, g2)


def compute_accumulator(sk: ZR, g1: G1, dataset: list[ZR]) -> G1:
    """Compute accumulator A = g1^{∏(sk + x)} for all x in dataset."""
    return g1 ** math.prod(sk + x for x in dataset)


def generate_proof(sk: ZR, g2: G2, dataset: list[ZR], subset: list[ZR]) -> G2:
    """Generate subset proof π = g2^{∏(sk + x) for x in (dataset \ subset)}."""
    dataset_dif = list(set(dataset) - set(subset))
    return g2 ** math.prod(sk + x for x in dataset_dif)


def verify_proof(g2: G2, proof: G2, acc_subset: G1, acc_dataset: G1) -> bool:
    """Check e(proof, acc_subset) == e(acc_dataset, g2)."""
    return pair(proof, acc_subset) == pair(acc_dataset, g2)


if __name__ == "__main__":
    sk, pk = generate_keys()

    N = 4
    dataset = [group.random(ZR) for _ in range(N)]

    acc_dataset = compute_accumulator(sk.sk, pk.g1, dataset)

    subset = [dataset[1]]
    acc_subset = compute_accumulator(sk.sk, pk.g1, subset)

    proof = generate_proof(sk.sk, pk.g2, dataset, subset)
    check = verify_proof(pk.g2, proof, acc_subset, acc_dataset)
    assert check
