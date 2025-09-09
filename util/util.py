import sys
from enum import Enum
from math import sqrt
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1

"""
Utility helpers shared across the project.

- group: Charm pairing group instance (BN254) used by crypto primitives.
- MAXINT: maximum platform integer used to bound random data generation.
- transpose: transpose a 2D list (rows <-> columns).
- hash_to_ZR: hash a G1 element into ZR using Charm's hash/serialize.
- encode_pair/decode_pair: Cantor-style pairing functions for (row, col).
- Aggregation: enumeration of supported aggregate operations.
"""

group = PairingGroup("BN254")

MAXINT = sys.maxsize


def transpose(dataset: list[list[int]]) -> list[list[int]]:
    """Transpose a 2D Python list (matrix)."""
    return list(map(list, zip(*dataset)))


def hash_to_ZR(value: G1) -> ZR:
    """Hash a group element in G1 to a scalar in ZR."""
    return group.hash(group.serialize(value))


def encode_pair(a: int, b: int) -> int:
    """Encode a pair of non-negative integers into a single integer."""
    return a * a + a + b if a >= b else a + b * b


def decode_pair(z: int) -> list:
    """Decode an integer back into the paired (a, b) using the inverse mapping."""
    sqrt_z = sqrt(z)
    sqz = sqrt_z * sqrt_z
    return [sqrt_z, z - sqz - sqrt_z] if (z - sqz) >= sqrt_z else [z - sqz, sqrt_z]


class Aggregation(str, Enum):
    """Supported aggregation types used by the ESA proofs."""
    NONE = "none"
    COUNT = "count"
    SUM = "sum"
    MIN = "min"
