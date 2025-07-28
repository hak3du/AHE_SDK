import oqs
import time

# Selected PQC KEMs for benchmarking (no Classic McEliece)
selected_kems = [
    "Kyber512",
    "Kyber768",
    "Kyber1024",
    "ML-KEM-512",
    "ML-KEM-768",
    "ML-KEM-1024",
    "sntrup761"
]

def benchmark_kem(kem_name):
    print(f"\nBenchmarking KEM: {kem_name}")
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            # Key generation timing
            start = time.perf_counter()
            public_key = kem.generate_keypair()
            keygen_time = time.perf_counter() - start

            # Encapsulation timing
            start = time.perf_counter()
            ciphertext, shared_secret_enc = kem.encap_secret(public_key)
            encap_time = time.perf_counter() - start

            # Decapsulation timing
            start = time.perf_counter()
            shared_secret_dec = kem.decap_secret(ciphertext)
            decap_time = time.perf_counter() - start

            # Verify secrets match
            secrets_match = (shared_secret_enc == shared_secret_dec)

            print(f"KeyGen time:        {keygen_time:.8f} seconds")
            print(f"Encapsulation time: {encap_time:.8f} seconds")
            print(f"Decapsulation time: {decap_time:.8f} seconds")
            print(f"Secrets match:      {secrets_match}")

    except Exception as e:
        print(f"Error benchmarking {kem_name}: {e}")

def main():
    for kem in selected_kems:
        benchmark_kem(kem)

if __name__ == "__main__":
    main()