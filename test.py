import oqs
import time

def benchmark_kem(kem_name):
    print(f"\nBenchmarking KEM: {kem_name}")
    try:
        with oqs.KeyEncapsulation(kem_name) as kem:
            # Try to generate keypair and handle unpacking robustly
            keypair = kem.generate_keypair()
            if isinstance(keypair, tuple) and len(keypair) == 2:
                public_key, secret_key = keypair
            else:
                # If just public_key returned, secret_key is internal
                public_key = keypair
                secret_key = None

            # Time KeyGen (just call again for timing)
            start = time.perf_counter()
            kem.generate_keypair()
            keygen_time = time.perf_counter() - start

            # Encapsulation timing
            start = time.perf_counter()
            if secret_key:
                ciphertext, shared_secret_enc = kem.encapsulate(public_key)
            else:
                ciphertext, shared_secret_enc = kem.encapsulate(public_key)
            encaps_time = time.perf_counter() - start

            # Decapsulation timing
            start = time.perf_counter()
            if secret_key:
                shared_secret_dec = kem.decapsulate(ciphertext, secret_key)
            else:
                shared_secret_dec = kem.decapsulate(ciphertext)
            decaps_time = time.perf_counter() - start

            secrets_match = (shared_secret_enc == shared_secret_dec)

            print(f"KeyGen time:        {keygen_time:.8f} seconds")
            print(f"Encapsulation time: {encaps_time:.8f} seconds")
            print(f"Decapsulation time: {decaps_time:.8f} seconds")
            print(f"Secrets match:      {secrets_match}")

    except Exception as e:
        print(f"Error benchmarking {kem_name}: {e}")

def main():
    # Use only enabled KEMs to avoid errors
    enabled_kems = oqs.get_enabled_kem_mechanisms()
    for kem in enabled_kems:
        benchmark_kem(kem)

if __name__ == "__main__":
    main()