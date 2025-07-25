import argparse
from core.core import encrypt_message, decrypt_latest

def interactive_menu():
    print("=== Adaptive Hashing Encryption SDK ===")

    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt the latest message")
        print("3. Exit")
        choice = input("Choice: ").strip()

        if choice == "1":
            message = input("Enter message to encrypt: ").strip()
            password = input("Enter password for encryption (remember this!): ").strip()
            encrypt_message(message, password)

        elif choice == "2":
            password = input("Enter password to decrypt: ").strip()
            try:
                decrypt_latest(password)
            except Exception as e:
                print(f"❌ Decryption error: {e}")

        elif choice == "3":
            print("Goodbye.")
            break

        else:
            print("Invalid choice. Please enter 1, 2 or 3.")

def main():
    parser = argparse.ArgumentParser(description="Adaptive Hashing Encryption (AHE) CLI Tool")
    parser.add_argument("--encrypt", type=str, help="Message to encrypt")
    parser.add_argument("--decrypt", action="store_true", help="Decrypt the latest message")
    parser.add_argument("--password", type=str, help="Password for encryption/decryption")

    args = parser.parse_args()

    if args.encrypt and args.password:
        encrypt_message(args.encrypt, args.password)

    elif args.decrypt and args.password:
        try:
            decrypt_latest(args.password)
        except Exception as e:
            print(f"❌ Decryption error: {e}")

    else:
        # If no arguments provided, run interactive mode
        interactive_menu()

if __name__ == "__main__":
    main()