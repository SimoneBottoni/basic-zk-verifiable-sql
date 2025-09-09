import random
import time
from typing import TypedDict
from charm.toolbox.pairinggroup import ZR

from util.util import group, Aggregation, MAXINT, transpose
from util.logger import Logger
from vector_commitments import pointproofs
from set_accumulator import ptt, esa
from inverted_index import inverted_index
from prover import prover
from verifier import verifier


class Config(TypedDict):
    n_col: int
    n_row: int
    selected_column: int
    aggregation: Aggregation
    filtered_row: int


class SK:
    def __init__(self, ptt_sk, vc_sk, esa_sk):
        self.ptt_sk = ptt_sk
        self.vc_sk = vc_sk
        self.esa_sk = esa_sk


class PK:
    def __init__(self, ptt_pk, vc_pk, esa_pk):
        self.ptt_pk = ptt_pk
        self.vc_pk = vc_pk
        self.esa_pk = esa_pk


def init_dataset(n_col, n_row):
    values = [random.randint(1, MAXINT) for _ in range(n_row)]
    dataset = [
        [random.sample(values, 1)[0] for _ in range(n_col)] for _ in range(n_row)
    ]
    return dataset


def init_dataset_as_ZR(dataset: list[list[int]]) -> list[list["ZR"]]:
    return [[group.init(ZR, el) for el in row] for row in dataset]


def generate_keys(n_row: int, min_value: ZR) -> tuple["SK", "PK"]:
    ptt_sk, ptt_pk = ptt.generate_keys()
    vc_sk, vc_pk = pointproofs.generate_keys(N=n_row)
    esa_sk, esa_pk = esa.generate_keys(min_value)

    return SK(ptt_sk, vc_sk, esa_sk), PK(ptt_pk, vc_pk, esa_pk)


def query(dataset, answer_size):
    answer = random.sample([[i] + dataset[i] for i in range(len(dataset))], answer_size)
    return answer


def answer_index(answer):
    answer_inv_index = inverted_index.build_subset(subset=answer)

    indexed_transposed_answer = transpose(answer)
    answer_indexes, transposed_answer = (
        indexed_transposed_answer[0],
        indexed_transposed_answer[1:],
    )

    return (
        answer_inv_index,
        answer_indexes,
        transposed_answer,
    )


def setup(sk: SK, pk: PK, transposed_dataset: list[list[ZR]]):
    # Correctness
    vc_cols = [
        pointproofs.commit(g1=pk.vc_pk.g1, messages=dataset_col, sk=sk.vc_sk.sk)
        for dataset_col in transposed_dataset
    ]
    esa_acc = [
        esa.compute_accumulator(sk=sk.esa_sk.sk, dataset=dataset_col)
        for dataset_col in transposed_dataset
    ]

    # Completeness
    inv_index = inverted_index.build(
        transposed_dataset, len(transposed_dataset), len(transposed_dataset[0])
    )
    committed_inv_index = inverted_index.build_committed(
        vc_pk=pk.vc_pk,
        vc_sk=sk.vc_sk,
        inverted_index=inv_index,
        ptt_sk=sk.ptt_sk,
        ptt_pk=pk.ptt_pk,
    )

    return vc_cols, inv_index, committed_inv_index, esa_acc


def run(config: Config, logger: Logger, round: int = None):
    """End-to-end demo run: keygen, commit, prove, and verify.

    This function is used in benchmarks and as a usage example; see README.
    """
    dataset_int = init_dataset(config["n_col"], config["n_row"])
    transposed_dataset_int = transpose(dataset_int)

    selected_column = config["selected_column"]

    min_value = min(transposed_dataset_int[selected_column])
    min_value = group.init(ZR, min_value)

    dataset = init_dataset_as_ZR(dataset_int)
    transposed_dataset = transpose(dataset)

    answer = query(dataset, config["filtered_row"])

    # ------- Setup -------
    start_time = time.time()
    sk, pk = generate_keys(config["n_row"], min_value)

    vc_cols, inv_index, verified_inverted_index, esa_acc = setup(
        sk, pk, transposed_dataset
    )

    answer_inv_index, answer_indexes, transposed_answer = answer_index(answer)
    setup_time = time.time() - start_time

    # ------- Prover -------
    start_time = time.time()
    if (
        config["aggregation"] == Aggregation.NONE
        or config["n_row"] != config["filtered_row"]
    ):
        correctness_proofs = prover.prove_correctness(
            vc_pk=pk.vc_pk,
            vc_sk=sk.vc_sk,
            vc_cols=vc_cols,
            transposed_answer=transposed_answer,
            answer_indexes=answer_indexes,
        )

    if config["aggregation"] != Aggregation.NONE:
        correctness_aggr_proof, correctness_aggr_proof_2, aggr_value = (
            prover.prove_aggr_correctness(
                aggregation=config["aggregation"],
                esa_pk=pk.esa_pk,
                esa_sk=sk.esa_sk,
                acc=esa_acc[selected_column],
                dataset=transposed_dataset[selected_column],
                min_value=min_value,
            )
        )

    prove_correctness_time = time.time() - start_time

    start_time = time.time()
    completeness_proofs = prover.prove_completeness(
        ptt_sk=sk.ptt_sk,
        ptt_pk=pk.ptt_pk,
        vc_sk=sk.vc_sk,
        vc_pk=pk.vc_pk,
        verified_inverted_index=verified_inverted_index,
        answer_inverted_index=answer_inv_index,
        inverted_index=inv_index,
    )
    prove_completeness_time = time.time() - start_time

    # ------- Verifier -------
    start_time = time.time()
    if (
        config["aggregation"] == Aggregation.NONE
        or config["n_row"] != config["filtered_row"]
    ):
        check = verifier.verify_correctness(
            vc_pk=pk.vc_pk,
            vc_cols=vc_cols,
            transposed_answer=transposed_answer,
            answer_indexes=answer_indexes,
            proofs=correctness_proofs,
        )
        assert check

    if config["aggregation"] != Aggregation.NONE:
        check = verifier.verify_aggr_correctness(
            aggregation=config["aggregation"],
            esa_pk=pk.esa_pk,
            acc=esa_acc[selected_column],
            proof=[correctness_aggr_proof, correctness_aggr_proof_2],
            value=aggr_value,
        )
        assert check
    verify_correctness_time = time.time() - start_time

    start_time = time.time()
    check = verifier.verify_completeness(
        vc_pk=pk.vc_pk,
        inverted_index=inv_index,
        verified_inverted_index=verified_inverted_index,
        answer_inverted_index=answer_inv_index,
        proofs=completeness_proofs,
    )
    assert check
    verify_completeness_time = time.time() - start_time

    print(
        f"{config['n_row']}, {config['aggregation']}, {config['filtered_row']}, {round}, {setup_time}, {prove_correctness_time}, {prove_completeness_time}, {verify_correctness_time}, {verify_completeness_time}",
        flush=True,
    )
    logger.log_results(
        list(
            map(
                str,
                [
                    config["n_row"],
                    config["aggregation"],
                    config["filtered_row"],
                    round,
                    setup_time,
                    prove_correctness_time,
                    prove_completeness_time,
                    verify_correctness_time,
                    verify_completeness_time,
                ],
            )
        )
    )


if __name__ == "__main__":
    config: Config

    config = {
        "n_col": 10,
        "n_row": 0,
        "selected_column": 0,
        "aggregation": Aggregation.NONE,
        "filtered_row": 0,
    }

    logger = Logger(
        list(
            map(
                str,
                [
                    "N Row",
                    "Aggregation",
                    "N Filtered Row",
                    "Round",
                    "Setup",
                    "Prove Correctness",
                    "Prove Completeness",
                    "Verify Correctness",
                    "Verify Completeness",
                ],
            )
        ),
    )

    # Query Type: SELECT * FROM x
    # filtered_data == data
    # no aggr proof
    for size in [1_000, 10_000, 30_000, 50_000, 75_000, 100_000]:
        config["n_row"] = size
        config["filtered_row"] = size
        config["aggregation"] = Aggregation.NONE

        for round in range(0, 3):
            logger.log_configuration(config)
            run(config, logger, round)

    # Query Type: SELECT AGGR(*) FROM x
    # filtered_data == data
    for size in [1_000, 10_000, 30_000, 50_000, 75_000, 100_000]:
        for aggregation in Aggregation:
            config["n_row"] = size
            config["filtered_row"] = size
            config["aggregation"] = aggregation

            for round in range(0, 3):
                logger.log_configuration(config)
                run(config, logger, round)

    # Query Type: SELECT * FROM x WHERE z
    # filtered_data < data
    # no aggr proof
    for size in [1_000, 10_000, 30_000, 50_000, 75_000, 100_000]:
        for filtered_size in [
            size // 1000,
            size // 100,
            size // 100,
            size // 10,
            size // 3,
        ]:
            config["n_row"] = size
            config["filtered_row"] = filtered_size

            for round in range(0, 3):
                logger.log_configuration(config)
                run(config, logger, round)

    # Query Type: SELECT AGGR(*) FROM x WHERE z
    # filtered_data < data
    for size in [1_000, 10_000, 30_000, 50_000, 75_000, 100_000]:
        for filtered_size in [
            size // 1000,
            size // 100,
            size // 100,
            size // 10,
            size // 3,
        ]:
            for aggregation in Aggregation:
                config["n_row"] = size
                config["filtered_row"] = filtered_size
                config["aggregation"] = aggregation

                for round in range(0, 3):
                    logger.log_configuration(config)
                    run(config, logger, round)
