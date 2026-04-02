# This file contains intentional hardcoded secrets for testing Zenvra's secrets scanner.
# None of these are real credentials.

import os
import boto3

# Hardcoded AWS credentials (should be flagged)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Hardcoded database URL with credentials (should be flagged)
DATABASE_URL = "postgres://admin:supersecretpassword@prod-db.example.com:5432/mydb"

# Hardcoded Stripe key (should be flagged)
STRIPE_KEY = "SK_LIVE_000000000000000000000000"

# Hardcoded GitHub token (should be flagged)
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

# Hardcoded generic password (should be flagged)
password = "my_super_secret_password_123"

# This is fine — reading from env
SAFE_API_KEY = os.environ.get("API_KEY")

# Private key (should be flagged)
PRIVATE_KEY = """
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VR...fake...key...data
-----END RSA PRIVATE KEY-----
"""

def connect_to_aws():
    """Connect to AWS using hardcoded credentials — BAD PRACTICE."""
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    return client


def main():
    print("This is a test file with intentional vulnerabilities.")
    client = connect_to_aws()
    print(f"Connected: {client}")


if __name__ == "__main__":
    main()
