import os

def create_file_if_not_exists(path):
    if not os.path.exists(path):
        with open(path, 'w') as f:
            f.write("# Placeholder for " + os.path.basename(path) + "\n")
        print(f"Created file: {path}")
    else:
        print(f"File already exists: {path}")

def create_sdk_v5_structure(base_path="AHE_SDK_v5"):
    structure = {
        "aes": ["aes.py", "utils.py"],
        "kdf": ["kdf.py", "utils.py"],
        "pqc": ["pqc.py", "utils.py"],
        "crypto": ["crypto.py", "utils.py"],
        "core": ["core.py", "utils.py"],
        "utils": ["entropy.py", "hashing.py", "anomaly.py"]
    }

    # Create base folder
    if not os.path.exists(base_path):
        os.mkdir(base_path)
        print(f"Created base folder: {base_path}")
    else:
        print(f"Base folder '{base_path}' already exists")

    # Create subfolders and files
    for folder, files in structure.items():
        folder_path = os.path.join(base_path, folder)
        if not os.path.exists(folder_path):
            os.mkdir(folder_path)
            print(f"Created folder: {folder_path}")
        else:
            print(f"Folder '{folder_path}' already exists")

        # Create placeholder files in each folder
        for file in files:
            file_path = os.path.join(folder_path, file)
            create_file_if_not_exists(file_path)

if __name__ == "__main__":
    create_sdk_v5_structure()