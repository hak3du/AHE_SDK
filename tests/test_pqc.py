"""
PQC Unit Tests for AHE SDK
===========================

This suite validates the robustness of our Post-Quantum Cryptography (PQC) Key Encapsulation Mechanism (KEM)
integration in the AHE SDK. It covers:

1. *Key Generation* for all supported KEM algorithms (FAST and STRONG sets).
2. *Encapsulation & Decapsulation Correctness*: Ensures that the derived shared secret remains consistent.
3. *Wrong Key Behavior*: Tests how KEM reacts when decapsulation is attempted with a different keypair.
   - EXPECTATION: No error is raised, but the derived shared secret differs. This is intended for IND-CCA2 security.
4. *Adaptive Selection Logic*: Tests whether anomaly-driven adaptive PQC algorithm selection works as intended.
5. *Performance Baseline*: Ensures PQC operations complete within a defined time threshold for practical deployments.

Supported PQC Algorithms:
- FAST: Kyber512, Kyber768, ML-KEM-512, ML-KEM-768
- STRONG: Kyber1024, ML-KEM-1024, sntrup761

Security Note:
- Wrong key decapsulation is NOT a vulnerability. It produces a different shared secret, preserving security.
- This design ensures resilience against chosen-ciphertext attacks and forward secrecy.
"""

import pytest
import time
from pqc.pqc import pqc_keypair, pqc_encapsulate, pqc_decapsulate, pqc_select_and_run, PQC_FAST_KEMS, PQC_STRONG_KEMS

# Define acceptable performance threshold (seconds)
PERFORMANCE_THRESHOLD = 0.5


@pytest.mark.parametrize("kem_name", PQC_FAST_KEMS + PQC_STRONG_KEMS)
def test_pqc_keypair_generation(kem_name):
    """
    Test that all supported PQC KEMs generate valid keypairs.

    EXPECTED:
    - kem: Valid KeyEncapsulation object
    - public_key: Non-empty bytes
    """
    kem, public_key = pqc_keypair(kem_name)
    assert kem is not None, f"KEM object is None for {kem_name}"
    assert isinstance(public_key, bytes), f"Public key is not bytes for {kem_name}"
    assert len(public_key) > 0, f"Public key is empty for {kem_name}"


@pytest.mark.parametrize("kem_name", ["Kyber512", "Kyber768"])
def test_pqc_encapsulate_and_decapsulate(kem_name):
    """
    Test correctness: Encapsulation followed by decapsulation
    MUST result in the same shared secret.
    """
    kem, public_key = pqc_keypair(kem_name)
    ciphertext, shared_secret = pqc_encapsulate(kem, public_key)
    assert isinstance(ciphertext, bytes), "Ciphertext is not bytes"
    assert isinstance(shared_secret, bytes), "Shared secret is not bytes"

    # Decapsulate and compare secrets
    decapsulated_ss = pqc_decapsulate(kem, ciphertext)
    assert decapsulated_ss == shared_secret, "Shared secret mismatch after decapsulation"


def test_pqc_wrong_key_decapsulation():
    """
    WRONG KEY TEST:
    - Encapsulate with kem1, decapsulate with kem2.
    EXPECTED:
    - No error thrown
    - Derived shared secret is DIFFERENT (by design for IND-CCA2 security).
    """
    kem1, pk1 = pqc_keypair("Kyber512")
    kem2, pk2 = pqc_keypair("Kyber512")

    # Encapsulate with kem1
    ciphertext, shared_secret = pqc_encapsulate(kem1, pk1)

    # Decapsulate with kem2 (wrong private key)
    wrong_secret = pqc_decapsulate(kem2, ciphertext)

    assert wrong_secret != shared_secret, "Wrong key should produce a different shared secret"


@pytest.mark.parametrize("anomaly", [True, False])
def test_pqc_select_and_run(anomaly):
    """
    Test adaptive PQC selection:
    - anomaly=True → Strong KEMs (e.g., Kyber1024)
    - anomaly=False → Fast KEMs (e.g., Kyber512)
    EXPECTED:
    - Successfully completes without exception.
    """
    kem_name, pk, ct, ss = pqc_select_and_run(anomaly)
    assert kem_name in (PQC_FAST_KEMS + PQC_STRONG_KEMS), "Returned KEM not in supported list"
    assert isinstance(ss, bytes) and len(ss) > 0, "Shared secret is invalid"


def test_pqc_performance():
    """
    Performance Benchmark:
    Ensure that PQC encapsulation + decapsulation completes under PERFORMANCE_THRESHOLD.
    """
    kem, pk = pqc_keypair("Kyber512")
    start = time.time()
    ct, ss = pqc_encapsulate(kem, pk)
    pqc_decapsulate(kem, ct)
    elapsed = time.time() - start

    assert elapsed < PERFORMANCE_THRESHOLD, f"PQC operation too slow: {elapsed:.4f}s"


# Optional: Add pytest markers for category-based filtering
pytestmark = pytest.mark.functional