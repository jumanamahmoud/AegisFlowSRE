"""
Sign in with a Supabase Auth account and print an access token for testing
the API by hand (until the dashboard login screen exists in Week 5).

Run from backend/:
    python -m scripts.get_token you@example.com

The password is read with getpass (not echoed, not stored). Use the token as:
    Authorization: Bearer <token>
Tokens expire after about an hour.
"""

from __future__ import annotations

import getpass
import os
import sys

from dotenv import load_dotenv
from supabase import create_client

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python -m scripts.get_token <email>")
    url = os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
    key = os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")  # sign-in uses the public key
    if not url or not key:
        sys.exit("SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY must be set in backend/.env")
    client = create_client(url, key)
    session = client.auth.sign_in_with_password(
        {"email": sys.argv[1], "password": getpass.getpass("Password: ")}
    ).session
    print(session.access_token)


if __name__ == "__main__":
    main()
