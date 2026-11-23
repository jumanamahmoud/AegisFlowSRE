from dotenv import load_dotenv
load_dotenv()

from database.neo4j_client import get_neo4j_client

SERVICES = [
    ("api-gateway", "API Gateway", "gateway"),
    ("checkout-service", "Checkout Service", "service"),
    ("order-service", "Order Service", "service"),
    ("payment-service", "Payment Service", "service"),
    ("fraud-service", "Fraud Detection", "service"),
    ("notification-service", "Notification Service", "service"),
    ("legacy-billing", "Legacy Billing", "service"),
]
EXTERNALS = [
    ("payment-db", "database"),
    ("redis-cache", "cache"),
]
# (source service, target service, protocol, active?)
SERVICE_EDGES = [
    ("api-gateway", "checkout-service", "HTTP", True),
    ("api-gateway", "order-service", "HTTP", True),
    ("checkout-service", "payment-service", "gRPC", True),
    ("order-service", "payment-service", "gRPC", True),
    ("order-service", "notification-service", "AMQP", True),
    ("payment-service", "fraud-service", "HTTP", True),
    ("payment-service", "legacy-billing", "HTTP", False),  # expired edge
]
# (source service, external system, protocol)
EXTERNAL_EDGES = [
    ("payment-service", "payment-db", "TCP"),
    ("payment-service", "redis-cache", "TCP"),
    ("fraud-service", "redis-cache", "TCP"),
]


def seed(client) -> None:
    with client.driver.session() as s:
        s.run(
            "UNWIND $rows AS r MERGE (n:Service {id: r.id}) "
            "SET n.name = r.name, n.type = r.type",
            rows=[{"id": i, "name": n, "type": t} for i, n, t in SERVICES],
        )
        s.run(
            "UNWIND $rows AS r MERGE (n:ExternalSystem {name: r.name}) SET n.type = r.type",
            rows=[{"name": n, "type": t} for n, t in EXTERNALS],
        )
        s.run(
            """
            UNWIND $rows AS e
            MATCH (a:Service {id: e.src}), (b:Service {id: e.dst})
            MERGE (a)-[r:DEPENDS_ON]->(b)
            SET r.protocol = e.protocol, r.valid_from = datetime('2025-01-01T00:00:00Z')
            FOREACH (x IN CASE WHEN e.active THEN [1] ELSE [] END | REMOVE r.valid_to)
            FOREACH (x IN CASE WHEN e.active THEN [] ELSE [1] END |
                     SET r.valid_to = datetime('2026-01-01T00:00:00Z'))
            """,
            rows=[{"src": a, "dst": b, "protocol": p, "active": act}
                  for a, b, p, act in SERVICE_EDGES],
        )
        s.run(
            """
            UNWIND $rows AS e
            MATCH (a:Service {id: e.src}), (b:ExternalSystem {name: e.dst})
            MERGE (a)-[r:DEPENDS_ON]->(b)
            SET r.protocol = e.protocol, r.valid_from = datetime('2025-01-01T00:00:00Z')
            REMOVE r.valid_to
            """,
            rows=[{"src": a, "dst": b, "protocol": p} for a, b, p in EXTERNAL_EDGES],
        )
        total = s.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    print(f"{total} nodes in graph")


def verify(client) -> None:
    """Run the real client methods and compare against what the seed data implies."""
    deps = {d["name"] for d in client.get_service_context("payment-service")}
    expected_deps = {"Fraud Detection", "payment-db", "redis-cache"}
    print("\npayment-service dependencies:", sorted(deps))
    print("  expected:", sorted(expected_deps),
          "->", "PASS" if deps == expected_deps else "FAIL")
    print("  legacy-billing excluded (expired edge):",
          "PASS" if "Legacy Billing" not in deps else "FAIL")

    blast = {b["id"]: b["hops"] for b in client.get_blast_radius("payment-service")}
    expected_blast = {"checkout-service": 1, "order-service": 1, "api-gateway": 2}
    print("\npayment-service blast radius:", blast)
    print("  expected:", expected_blast,
          "->", "PASS" if blast == expected_blast else "FAIL")


if __name__ == "__main__":
    client = get_neo4j_client()
    try:
        seed(client)
        verify(client)
    finally:
        client.close()