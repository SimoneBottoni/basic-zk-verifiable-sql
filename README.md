# basic-zk-verifiable-sql
A minimal zero-knowledge-style verification system that uses:
- Vector commitments (PointProofs) to prove value-correctness for selected rows;
- Set accumulators to prove simple aggregations (COUNT, SUM, MIN);
- A committed inverted index to prove completeness (returned keys actually exist in the committed dataset).

### Requirements
- Python 3.9+
- Charm-Crypto v.0.50 (https://github.com/JHUISI/charm)

## Usage
This example runs the full pipeline (keygen, commit, prove, verify) once on a small random dataset using the convenient main.run function.
```python
from util.util import Aggregation
from util.logger import Logger
from main import run, Config

config: Config = {
    "n_col": 5,            # number of columns in the table
    "n_row": 1000,         # number of rows in the table
    "selected_column": 0,  # the column to aggregate on (for SUM/MIN/COUNT)
    "aggregation": Aggregation.SUM,  # Aggregation.NONE, COUNT, SUM, MIN
    "filtered_row": 100,   # how many rows get returned (subsampled answer)
}

logger = Logger([
    "N Row", "Aggregation", "N Filtered Row", "Round",
    "Setup", "Prove Correctness", "Prove Completeness",
    "Verify Correctness", "Verify Completeness",
])

# Single demo run
run(config, logger, round=0)
```

## Repository Structure (high level)

```markdown
project-root/
│
├── benches/ # Benchmarking utilities and performance tests
│ └── test_data/ # Sample data used during benchmarking
│
├── vector_commitments/
│ ├── pointproofs.py # PointProofs scheme, commit/prove/verify/aggregate
├── set_accumulator/
│ ├── esa.py, ptt.py # accumulator primitives and aggregation proofs
├── inverted_index/
│ ├── inverted_index.py # build and commit an inverted index for completeness
├── prover/
│ ├── prover.py # constructs correctness/completeness/aggregation proofs
├── verifier/
│ ├── verifier.py # verifies the corresponding proofs
│
├── main.py
│
└── README.md # Project documentation (this file)
```

## Disclaimer
This is a research-grade implementation, meant for experimentation and educational use.
Not suitable for production deployment.

---

## Acknowledgements

This work was supported in part by project SERICS (PE00000014) under the NRRP MUR program funded by the EU - NGEU.