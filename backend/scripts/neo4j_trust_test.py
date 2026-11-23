from dotenv import load_dotenv
load_dotenv()
import os, certifi
from neo4j import GraphDatabase, TrustCustomCAs

host = os.environ["NEO4J_URI"].split("://")[1]
auth = (os.environ["NEO4J_USER"], os.environ["NEO4J_PASSWORD"])
print("NEO4J_CA_BUNDLE in env:", os.environ.get("NEO4J_CA_BUNDLE"))

for label, kw in [
    ("system store", {}),
    ("certifi", {"trusted_certificates": TrustCustomCAs(certifi.where())}),
]:
    try:
        d = GraphDatabase.driver(f"bolt://{host}", auth=auth, encrypted=True, **kw)
        d.verify_connectivity()
        print(label, "-> OK")
        d.close()
    except Exception as e:
        print(label, "-> FAILED:", type(e).__name__, str(e)[:200])