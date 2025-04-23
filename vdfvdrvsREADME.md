Playbook: Secure Password Storage Implementation
Source: https://github.com/mrlopez-ale/Secure-Password-Storage
Objective:
Demonstrate the correct, secure method for storing user passwords using modern hashing techniques (specifically bcrypt via the passlib library).
Highlight the importance of unique salts per user.
Contrast secure methods with common insecure practices like plaintext storage or using unsalted fast hashes (e.g., MD5).
Provide a clear understanding of why hashing is the preferred method over encryption for password storage.
1. Prerequisites & Setup:
Environment: Python 3.x installed.
Package Manager: pip (Python package installer) available.
Required Library: passlib with the bcrypt backend.
Installation Command: Open your terminal or command prompt and run:
pip install "passlib[bcrypt]"
Troubleshooting Note: bcrypt sometimes requires system build tools (like C compilers). If the installation fails, consult the bcrypt documentation specific to your operating system or try installing the components separately:
pip install passlib bcrypt
4. Procedure: Demonstration Script (secure_password_demo.py)
(Note: This section describes how to use a demonstration script based on the provided information. The actual Python code for secure_password_demo.py should be obtained separately.)
Purpose: This Python script simulates user registration and login to illustrate secure hashing and verification, alongside examples of insecure methods.
Execution Steps:
Ensure you have the secure_password_demo.py file.
Navigate to the directory containing the file using your terminal or command prompt.
Run the script using the Python interpreter:
python secure_password_demo.py


Expected Observations from Script Output:
Secure Hashing: Observe the process of generating a bcrypt hash during the simulated registration.
Hash Format: Note the structure of the stored bcrypt hash string. It typically includes markers for the algorithm ($2b$), the cost factor, the salt, and the resulting hash digest, all encoded together.
Verification Success: See successful login validation when the correct password is provided.
Verification Failure: See failed login validation when an incorrect password is provided.
Insecure Examples: Observe demonstrations of plaintext storage and unsalted MD5 hashing, clearly showing why these are weak and easily compromised.
4. Core Principles of Secure Password Hashing:
A. Hashing (Not Encryption): The Cornerstone
Hashing: A one-way cryptographic function transforming input (password) into a fixed-size, irreversible string (hash). It's computationally infeasible to get the original password from the hash.
Encryption: A two-way process (encrypt/decrypt) requiring a key. Unsuitable for password storage due to the risk of key compromise exposing all passwords.
Key Point: We store the hash of the password, never the password itself.
B. Salting: Adding Uniqueness & Defeating Rainbow Tables
Salt: A unique, random piece of data generated for each password before hashing.
Importance: Prevents attackers from using "Rainbow Tables" (precomputed hash lookups). By adding a unique salt (hash(password + salt)), even identical passwords result in different final hashes for different users.
Storage: The salt is not secret and is typically stored alongside the hash (often embedded within the hash string itself, as passlib does).
C. Strong Hashing Algorithm: Choosing the Right Tool
Requirement: Use algorithms specifically designed for password hashing – deliberately slow and computationally expensive to hinder brute-force attacks.
Recommended Choices: bcrypt, Argon2 (often considered the current best practice), scrypt.
Algorithms to Avoid: MD5, SHA-1, SHA-256 (when used alone without proper salting and key stretching/cost factors). These are too fast and vulnerable.
D. Cost Factor (Work Factor / Rounds): Balancing Security & UX
Cost Factor: A configurable parameter (e.g., in bcrypt) controlling the computational cost (time) of hashing.
Trade-off: Higher cost factor = more security against brute-force, but slower hashing/verification.
Balance: passlib uses sensible defaults. Adjust based on hardware and security needs.
5. Design Rationale: Why Hashing is Used (Not Encryption)
Primary Goal: Verify a user's identity without storing their actual password in a recoverable format.
Hashing Enables Secure Verification:
The one-way nature makes reversing the hash infeasible.
Verification Process: Hash the login attempt's password (using the stored salt) and compare it to the stored hash.
Security Benefit: The system never needs the plaintext password after registration.
Encryption's Unsuitability:
Requires secure key management, which is complex and creates a single point of failure. If the key is compromised, all encrypted passwords can be revealed.
Conclusion: Hashing aligns perfectly with the goal of secure verification without storing the secret, avoiding the risks of encryption key management.
6. Why This Approach (bcrypt via passlib) is Secure:
Unique Salts: passlib automatically generates a unique salt for every hash, defeating rainbow table attacks.
Adaptive & Slow: bcrypt is computationally expensive and has an adjustable cost factor, making brute-force guessing significantly harder and slower compared to fast hashes like MD5.
Standard & Vetted: bcrypt is a widely used and scrutinized industry standard. passlib provides a robust and correct implementation.
Ease of Use: passlib abstracts away the complexities of salt generation, encoding, and verification logic.
7. Comparison with Insecure Methods:
Plaintext:
Risk: Storing passwords as readable text. The most dangerous method.
Impact: If the data store is breached, all user passwords are immediately exposed. Never do this.
Unsalted Fast Hashes (e.g., MD5, SHA1):
Vulnerable to Rainbow Tables: No unique salt means identical passwords always produce the same hash, making them trivial to look up in precomputed tables.
Too Fast: These algorithms execute extremely quickly, allowing attackers to test billions of password guesses per second on modern hardware, making brute-force feasible.


8. Overall Conclusion:
Protecting user passwords is paramount. Always use a strong, adaptive hashing algorithm like bcrypt or Argon2, ensuring each password hash uses a unique salt. passlib in Python provides an excellent and easy way to implement these best practices. Avoid plaintext storage and weak/fast hashing algorithms entirely.
