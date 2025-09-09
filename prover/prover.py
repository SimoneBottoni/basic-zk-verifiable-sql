from collections import defaultdict
from charm.toolbox.pairinggroup import ZR, G1

from vector_commitments import pointproofs
from set_accumulator import ptt, esa

from vector_commitments.pointproofs import PK as VC_PK, SK as VC_SK
from set_accumulator.esa import PK as ESA_PK, SK as ESA_SK
from set_accumulator.ptt import PK as PTT_PK, SK as PTT_SK

from util.util import hash_to_ZR, group, Aggregation

"""
Prover module: builds non-interactive proofs.

- Value correctness (PointProofs aggregated proofs for selected rows)
- Aggregation correctness (ESA: COUNT, SUM, MIN)
- Completeness via inverted index (commit [key, acc_hash] and link to top commit)
"""

def prove_correctness(
    vc_pk: VC_PK,
    vc_sk: VC_SK,
    vc_cols: list[G1],
    transposed_answer: list[list[ZR]],
    answer_indexes: list[int],
) -> list[G1]:
    """Generate aggregate proofs of value-correctness for each column.

    Returns a list of aggregated proofs (one per column) covering answer_indexes.
    """
    proofs_col = [
        [
            pointproofs.generate_proof(
                pk_g1=vc_pk.pk_g1,
                sk=vc_sk.sk,
                v_commit=vc,
                index=answer_index,
                message=col_value,
            )
            for answer_index, col_value in zip(answer_indexes, col)
        ]
        for vc, col in zip(vc_cols, transposed_answer)
    ]

    return [
        pointproofs.aggregate_proofs(
            v_commit=vc, messages=col, indexes=answer_indexes, proofs=proofs
        )
        for vc, col, proofs in zip(vc_cols, transposed_answer, proofs_col)
    ]


def prove_aggr_correctness(
    aggregation: Aggregation,
    esa_pk: ESA_PK,
    esa_sk: ESA_SK,
    acc: ZR,
    dataset: list[ZR],
    min_value: ZR,
):
    """Generate aggregation proof and the aggregated value.

    Returns (proof_1, proof_2_or_None, value).
    """
    proof = group.init(G1, 0)
    proof_2 = None
    value = min_value
    if aggregation == Aggregation.COUNT:
        proof, value = esa.generate_count_proof(
            g2=esa_pk.g2, sk=esa_sk.sk, acc=acc, dataset=dataset
        )
    elif aggregation == Aggregation.SUM:
        proof, proof_2, value = esa.generate_sum_proof(
            g2=esa_pk.g2, sk=esa_sk.sk, acc=acc, dataset=dataset
        )
    elif aggregation == Aggregation.MIN:
        proof, _ = esa.generate_min_proof(
            g2=esa_pk.g2, sk=esa_sk.sk, acc=acc, min=min_value
        )

    return proof, proof_2, value


def prove_completeness(
    ptt_sk: PTT_SK,
    ptt_pk: PTT_PK,
    vc_sk: VC_SK,
    vc_pk: VC_PK,
    verified_inverted_index: G1,
    answer_inverted_index: dict[ZR, list[int]],
    inverted_index: dict[ZR, list[int]],
) -> dict[ZR, dict[str, object]]:
    """Create proofs that every returned key appears in the committed inverted index.

    Returns a dict keyed by ZR keys with components needed by the verifier.
    """
    proofs = defaultdict(tuple)
    for key, value in answer_inverted_index.items():
        acc = ptt.compute_accumulator(sk=ptt_sk.sk, g1=ptt_pk.g1, dataset=value)
        acc_hash = hash_to_ZR(acc)

        vsa_pair = [key, acc_hash]
        vsa = pointproofs.commit(g1=vc_pk.g1, messages=vsa_pair, sk=vc_sk.sk)
        vsa_indexes = [0, 1]

        proof_key = pointproofs.generate_proof(
            pk_g1=vc_pk.pk_g1,
            sk=vc_sk.sk,
            v_commit=vsa,
            index=vsa_indexes[0],
            message=vsa_pair[0],
        )
        proof_sa = pointproofs.generate_proof(
            pk_g1=vc_pk.pk_g1,
            sk=vc_sk.sk,
            v_commit=vsa,
            index=vsa_indexes[1],
            message=vsa_pair[1],
        )

        proofs_1 = pointproofs.aggregate_proofs(
            v_commit=vsa,
            messages=vsa_pair,
            indexes=vsa_indexes,
            proofs=[proof_key, proof_sa],
        )

        proofs_2 = pointproofs.generate_proof(
            pk_g1=vc_pk.pk_g1,
            sk=vc_sk.sk,
            v_commit=verified_inverted_index,
            index=list(inverted_index.keys()).index(key),
            message=key,
        )

        proofs[key] = {
            "acc_hash": acc_hash,
            "vc": vsa,
            "proofs_1": proofs_1,
            "proofs_2": proofs_2,
        }

    return proofs
