import hashlib

def calculate_sha256(filepath):
    """
    Calculate the SHA-256 hash of a file at the given filepath.
    Reads the file in binary chunks (64KB) to avoid memory overload.
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash in blocks of 64K
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
