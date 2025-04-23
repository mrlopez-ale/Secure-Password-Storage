#  Secure Password Handling with bcrypt and passlib
#  This script demonstrates secure password hashing and verification
#  using bcrypt via the passlib library, and contrasts it with
#  insecure methods like unsalted MD5 hashing.

import hashlib
import os
# passlib is a comprehensive password hashing library for Python.
# It supports various algorithms like bcrypt, Argon2, scrypt, etc.
from passlib.context import CryptContext

# --- Secure Password Handling ---

# 1. Configure CryptContext
#    - This object manages password hashing policies.
#    - 'schemes': Specifies the list of allowed hashing algorithms.
#      We'll use 'bcrypt', a strong and widely recommended algorithm.
#    - 'deprecated="auto"': Tells passlib to automatically use stronger
#      settings (like increased cost factor) if the defaults become outdated.
pwd_context = CryptContext(
        schemes=["bcrypt"],
        deprecated="auto",
)

def hash_password_securely(password: str) -> str:
    """
    Hashes a password using the configured CryptContext (bcrypt).

    Args:
        password: The plaintext password to hash.

    Returns:
        The resulting hash string, which includes algorithm identifier,
        cost factor, salt, and the hash itself. Passlib handles unique
        salt generation automatically for each call.
    """
    print("   Hashing password using bcrypt...")
    hashed_password = pwd_context.hash(password)
    print(f"   Generated Hash: {hashed_password[:30]}...") # Print prefix for brevity
    return hashed_password

def verify_password_securely(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plaintext password against a stored hash string.

    Args:
        plain_password: The plaintext password attempt from the user.
        hashed_password: The stored hash string from the database.

    Returns:
        True if the password matches the hash, False otherwise.
        Passlib automatically extracts the salt and settings (algo, cost)
        from the hash string for verification.
    """
    print(f"   Verifying '{plain_password}' against stored hash...")
    try:
        is_valid = pwd_context.verify(plain_password, hashed_password)
        print(f"   Verification result: {is_valid}")
        return is_valid
    except Exception as e:
        # Catch potential errors, e.g., if the hash string is malformed
        # or doesn't match the configured schemes in the context.
        print(f"   Error during verification: {e}")
        return False

# --- Insecure Password Handling (FOR DEMONSTRATION ONLY - DO NOT USE!) ---

def hash_password_insecure_md5_nosalt(password: str) -> str:
    """
    Hashes a password using MD5 without any salt.
    THIS IS HIGHLY INSECURE and shown only for contrast.

    Args:
        password: The plaintext password.

    Returns:
        The MD5 hash as a hexadecimal string.
    """
    print("   Hashing password using MD5 (Insecure)...")
    # Convert password string to bytes, required by hashlib
    password_bytes = password.encode('utf-8')
    # Calculate MD5 hash
    md5_hash = hashlib.md5(password_bytes).hexdigest()
    print(f"   Generated MD5 Hash: {md5_hash}")
    return md5_hash

def verify_password_insecure_md5_nosalt(plain_password: str, stored_md5_hash: str) -> bool:
    """
    Verifies a password against a stored unsalted MD5 hash.
    THIS IS INSECURE.

    Args:
        plain_password: The plaintext password attempt.
        stored_md5_hash: The stored MD5 hash.

    Returns:
        True if the re-hashed password matches the stored hash, False otherwise.
    """
    print(f"   Verifying '{plain_password}' against stored MD5 hash...")
    # Re-hash the attempt and compare directly
    is_valid = hash_password_insecure_md5_nosalt(plain_password) == stored_md5_hash
    print(f"   Verification result: {is_valid}")
    return is_valid

# --- Demonstration Script ---

if __name__ == "__main__":
    # Simulate a user choosing a password during registration
    user_password = "MyP@ssw0rd!123"

    print("="*60)
    print(" SECURE PASSWORD HANDLING DEMO (bcrypt via passlib)")
    print("="*60)

    # --- Simulate Registration ---
    print("\n[REGISTRATION PHASE]")
    print(f"User chose password: '{user_password}'")
    # Hash the password securely using bcrypt and store the result
    # In a real app, this hash would be saved in the user database
    stored_secure_hash = hash_password_securely(user_password)
    print(f"Secure hash stored in database:\n'{stored_secure_hash}'")
    # Note the structure: $2b$ (bcrypt) $12$ (cost) $salt (22 chars) hash (31 chars)

    # --- Simulate Login Attempts ---
    print("\n[LOGIN PHASE]")

    # Attempt 1: Correct Password
    print("\nAttempt 1: User enters CORRECT password")
    login_attempt_correct = user_password
    is_valid_correct = verify_password_securely(login_attempt_correct, stored_secure_hash)
    print(f"--> Login Success: {is_valid_correct}")

    # Attempt 2: Incorrect Password
    print("\nAttempt 2: User enters INCORRECT password")
    login_attempt_incorrect = "WrongPassword!"
    is_valid_incorrect = verify_password_securely(login_attempt_incorrect, stored_secure_hash)
    print(f"--> Login Success: {is_valid_incorrect}")

    print("\n" + "="*60)
    print(" INSECURE PASSWORD HANDLING EXAMPLES (DO NOT USE!)")
    print("="*60)

    # --- Example 1: Storing Plaintext (The Absolute Worst) ---
    print("\n[INSECURE METHOD 1: Plaintext Storage]")
    stored_plaintext = user_password
    print(f"Password stored as: '{stored_plaintext}' <--- EXTREMELY DANGEROUS!")
    print("Why it's bad: If the database leaks, all passwords are instantly compromised.")

    # --- Example 2: Storing Unsalted MD5 Hash (Also Very Bad) ---
    print("\n[INSECURE METHOD 2: Unsalted MD5 Hash]")
    print(f"Using the same password: '{user_password}'")
    # Generate the insecure hash
    stored_md5_hash = hash_password_insecure_md5_nosalt(user_password)
    print(f"Insecure MD5 hash stored in database: '{stored_md5_hash}'")

    # Verify MD5 with correct password
    print("\nVerifying correct password against MD5 hash:")
    verify_md5_correct = verify_password_insecure_md5_nosalt(user_password, stored_md5_hash)
    print(f"--> MD5 Verification Result: {verify_md5_correct}")

    # Verify MD5 with incorrect password
    print("\nVerifying incorrect password against MD5 hash:")
    verify_md5_incorrect = verify_password_insecure_md5_nosalt("WrongPassword!", stored_md5_hash)
    print(f"--> MD5 Verification Result: {verify_md5_incorrect}")

    print("\nWhy unsalted MD5 is bad:")
    print("  - Too Fast: MD5 computes extremely quickly, making brute-force attacks (trying millions/billions of passwords per second) easy with modern hardware.")
    print("  - No Salt: Every user with the same password gets the same hash. Attackers use 'Rainbow Tables' - precomputed lists of common passwords and their MD5 hashes - to instantly crack these.")
    print("  - Collision Vulnerabilities: While less critical for password hashing than for data integrity, MD5 has known weaknesses.")

    print("\n" + "="*60)
    print(" CONCLUSION: Always use a strong, salted, adaptive hashing algorithm")
    print("             like bcrypt or Argon2 via a standard library like passlib.")
    print("="*60)
