import ssl, tempfile, os

from dotenv import load_dotenv
from urllib.parse import urlparse
load_dotenv()
host = urlparse(os.environ["NEO4J_URI"]).hostname
pem = ssl.get_server_certificate((host, 7687))
with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
    f.write(pem)
info = ssl._ssl._test_decode_cert(f.name)
os.unlink(f.name)
print("issuer :", info["issuer"])
print("subject:", info["subject"])