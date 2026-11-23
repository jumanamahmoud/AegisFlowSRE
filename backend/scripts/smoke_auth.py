"""
Live login check: signs in with a real Supabase Auth account and runs the API
(in-process, real token verification + real role lookup) to confirm that only
logged-in users get in and that roles are enforced.

Run from backend/:
    python -m scripts.smoke_auth you@example.com

The password is read with getpass (not echoed, not stored). Nothing is written
to the database except reads.
"""

from __future__ import annotations

import getpass
import os
import sys

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
os.environ.setdefault("AEGIS_LOG_LEVEL", "WARNING")


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: python -m scripts.smoke_auth <email>")
    from fastapi.testclient import TestClient
    from supabase import create_client

    import main as app_main

    url = os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL")
    key = os.environ.get("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
    if not url or not key:
        sys.exit("SUPABASE_URL and NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY must be set in backend/.env")
    session = create_client(url, key).auth.sign_in_with_password(
        {"email": sys.argv[1], "password": getpass.getpass("Password: ")}
    ).session
    token = session.access_token
    good = {"Authorization": f"Bearer {token}"}
    tampered = {"Authorization": f"Bearer {token[:-4]}AAAA"}

    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, note: str) -> None:
        results.append((name, ok, note))

    with TestClient(app_main.app) as c:
        me = c.get("/auth/me", headers=good)
        role = me.json().get("role") if me.status_code == 200 else None
        check("real token accepted (/auth/me)", me.status_code == 200, f"{me.status_code}, role={role}")
        probe = "/incidents/00000000-0000-0000-0000-000000000000"  # unknown id: 404 means "got past login"
        r = c.get(probe, headers=good)
        check("logged-in user reaches incidents API", r.status_code == 404, f"{r.status_code} (404 = authorised, not found)")
        r = c.get(probe)
        check("no token rejected", r.status_code == 401, str(r.status_code))
        r = c.get(probe, headers=tampered)
        check("tampered token rejected", r.status_code == 401, str(r.status_code))
        r = c.get("/admin/users", headers=good)
        expect = 200 if role == "admin" else 403
        check("admin endpoint follows role", r.status_code == expect, f"{r.status_code} (expected {expect})")
        r = c.get("/health")
        check("/health stays public", r.status_code == 200, str(r.status_code))

    width = max(len(n) for n, _, _ in results)
    print()
    for name, ok, note in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name.ljust(width)}  {note}")
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


if __name__ == "__main__":
    main()
