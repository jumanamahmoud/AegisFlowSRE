from dotenv import load_dotenv
load_dotenv()
import os, socket
from urllib.parse import urlparse
from neo4j import GraphDatabase

uri = os.environ["NEO4J_URI"]
host = urlparse(uri).hostname
print("scheme:", uri.split("://")[0], "| host:", host)

try:
    print("DNS ->", socket.gethostbyname(host))
    socket.create_connection((host, 7687), timeout=8).close()
    print("port 7687 reachable")
except Exception as e:
    print("NETWORK PROBLEM:", repr(e))

for scheme in ("neo4j+s", "bolt+s"):
    try:
        d = GraphDatabase.driver(f"{scheme}://{host}",
                                 auth=(os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"]))
        d.verify_connectivity()
        print(scheme, "-> OK")
        d.close()
    except Exception as e:
        print(scheme, "-> FAILED:", type(e).__name__, e)