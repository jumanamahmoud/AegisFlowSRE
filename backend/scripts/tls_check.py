import os
import ssl, socket
import certifi


from dotenv import load_dotenv
from urllib.parse import urlparse
load_dotenv()
host = urlparse(os.environ["NEO4J_URI"]).hostname

def try_tls(label, tweak=None):
    ctx = ssl.create_default_context()
    if tweak:
        tweak(ctx)
    try:
        with socket.create_connection((host, 7687), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                print(label, "-> OK", t.version())
    except ssl.SSLCertVerificationError as e:
        print(label, "-> CERT FAILED:", e.verify_message)
    except Exception as e:
        print(label, "-> FAILED:", repr(e))

try_tls("default")
try_tls("non-strict",
        lambda c: setattr(c, "verify_flags", c.verify_flags & ~ssl.VERIFY_X509_STRICT))
try_tls("certifi", lambda c: c.load_verify_locations(certifi.where()))