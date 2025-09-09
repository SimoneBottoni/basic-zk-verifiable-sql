from collections import defaultdict
from charm.toolbox.pairinggroup import ZR, G1

from util.util import encode_pair, hash_to_ZR

from vector_commitments import pointproofs
from set_accumulator import ptt

from vector_commitments.pointproofs import PK as VC_PK, SK as VC_SK
from set_accumulator.ptt import SK as PTT_SK, PK as PTT_PK


def build(data: list[list[ZR]], n_row: int, n_col: int) -> dict[ZR, list[int]]:
    """Build an inverted index mapping value -> list of encoded (row, col) pairs."""
    inverted_index = defaultdict(list)
    for i in range(n_row):
        for j in range(n_col):
            inverted_index[data[i][j]] += [encode_pair(i, j)]

    return inverted_index


def build_subset(subset: list[list[ZR]]) -> dict[ZR, list[int]]:
    """Build the inverted index for a subset of rows (answer set)."""
    subset_inverted_index = defaultdict(list)
    for row in subset:
        for idx, value in enumerate(row[1:]):
            subset_inverted_index[value] += [encode_pair(row[0], idx)]

    return subset_inverted_index


def build_committed(
    vc_pk: VC_PK,
    vc_sk: VC_SK,
    inverted_index: dict[ZR, list[int]],
    ptt_sk: PTT_SK,
    ptt_pk: PTT_PK,
) -> list[ZR]:
    """Commit to the inverted index: commit each [key, acc_hash], then commit the list.

    Returns the top-level commitment to the list of per-key commitments.
    """
    vsa_pairs = []
    for key, value in inverted_index.items():
        acc = ptt.compute_accumulator(sk=ptt_sk.sk, g1=ptt_pk.g1, dataset=value)
        vsa_pairs.append([key, hash_to_ZR(acc)])

    vsa_list = [
        hash_to_ZR(value=pointproofs.commit(g1=vc_pk.g1, messages=pair, sk=vc_sk.sk))
        for pair in vsa_pairs
    ]

    vsa = pointproofs.commit(g1=vc_pk.g1, messages=vsa_list, sk=vc_sk.sk)
    return vsa
