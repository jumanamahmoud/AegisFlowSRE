from dotenv import load_dotenv
load_dotenv()
import os
from database.neo4j_client import get_neo4j_client

c = get_neo4j_client()
print("user:", os.environ["NEO4J_USER"])
for db in ("system", "neo4j"):
    try:
        with c.driver.session(database=db) as s:
            if db == "system":
                print("databases:", [r["name"] for r in s.run("SHOW DATABASES")])
            else:
                print("neo4j db node count:", s.run("MATCH (n) RETURN count(n) AS c").single()["c"])
    except Exception as e:
        print(db, "->", type(e).__name__, str(e)[:150])
c.close()