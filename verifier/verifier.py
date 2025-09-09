from charm.toolbox.pairinggroup import ZR, G1

from vector_commitments import pointproofs
from set_accumulator import esa

from vector_commitments.pointproofs import PK as VC_PK
from set_accumulator.esa import PK as ESA_PK

from util.util import Aggregation

"""
Verifier module: checks proofs produced by the prover.

- Value correctness with vector commitments (PointProofs)
- Aggregation correctness for COUNT/SUM/MIN (ESA)
- Completeness of answer using the committed inverted index
"""

def verify_correctness(
    vc_pk: VC_PK,
    vc_cols: list[G1],
    transposed_answer: list[list[ZR]],
    answer_indexes: list[int],
    proofs: list[list[G1]],
) -> bool:
    """Verify value-correctness of the returned rows against vector commitments.

    Parameters:
    - vc_pk: public key for the vector commitment scheme.
    - vc_cols: commitments of each column (commitment per column of the dataset).
    - transposed_answer: the answer matrix transposed (columns as lists of ZR values).
    - answer_indexes: indexes of the selected rows in the original dataset.
    - proofs: aggregate proofs for each column corresponding to answer_indexes.

    Returns True if all aggregate proofs verify, False otherwise.
    """
    for vc, col, proof in zip(vc_cols, transposed_answer, proofs):
        if not pointproofs.verify_aggregate_proofs(
            g2=vc_pk.g2,
            pk_g2=vc_pk.pk_g2,
            pk_gt=vc_pk.pk_gt,
            v_commit=vc,
            messages=col,
            indexes=answer_indexes,
            aggregate_proofs=proof,
        ):
            return False

    return True


def verify_aggr_correctness(
    aggregation: Aggregation,
    esa_pk: ESA_PK,
    acc: ZR,
    proof: list[ZR],
    value: ZR,
) -> bool:
    """Verify aggregation correctness (COUNT, SUM, MIN) over a committed set.

    The proof format depends on the aggregation type:
    - COUNT: proof = [proof_count]
    - SUM:   proof = [proof_sum_1, proof_sum_2]
    - MIN:   proof = [proof_min]
    """
    check = False

    if aggregation == Aggregation.COUNT:
        check = esa.verify_count_proof(
            esa_pk.g1, esa_pk.g2, esa_pk.pk_count, acc, proof[0], value
        )
    elif aggregation == Aggregation.SUM:
        check = esa.verify_sum_proof(
            esa_pk.g1,
            esa_pk.g2,
            esa_pk.pk_sum,
            esa_pk.pk_count,
            acc,
            proof[0],
            proof[1],
            value,
        )
    elif aggregation == Aggregation.MIN:
        check = esa.verify_min_proof(
            esa_pk.g1, esa_pk.g2, esa_pk.pk_min, esa_pk.pk_min_2, acc, proof[0]
        )

    return check


def verify_completeness(
    vc_pk: VC_PK,
    inverted_index: dict[ZR, list[int]],
    verified_inverted_index: G1,
    answer_inverted_index: dict[ZR, list[int]],
    proofs: dict[ZR, dict[str, object]],
) -> bool:
    """Verify completeness: every key in the answer is present in the committed inverted index.

    proofs[key] must contain:
    - "vc": G1 commitment to [key, acc_hash]
    - "acc_hash": ZR hash of the accumulator for the answer's posting list
    - "proofs_1": aggregated proof for the pair [key, acc_hash]
    - "proofs_2": single proof that key appears at its position in verified_inverted_index
    """
    for key, value in answer_inverted_index.items():
        check_1 = pointproofs.verify_aggregate_proofs(
            g2=vc_pk.g2,
            pk_g2=vc_pk.pk_g2,
            pk_gt=vc_pk.pk_gt,
            v_commit=proofs[key]["vc"],
            messages=[key, proofs[key]["acc_hash"]],
            indexes=[0, 1],
            aggregate_proofs=proofs[key]["proofs_1"],
        )
        check_2 = pointproofs.verify_proof(
            g2=vc_pk.g2,
            pk_g2=vc_pk.pk_g2,
            pk_gt=vc_pk.pk_gt,
            v_commit=verified_inverted_index,
            message=key,
            index=list(inverted_index.keys()).index(key),
            proof_i=proofs[key]["proofs_2"],
        )

        if not (check_1 and check_2):
            return False

    return True
