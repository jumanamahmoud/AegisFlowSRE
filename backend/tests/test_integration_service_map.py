"""
backend/tests/test_integration_service_map.py
==============================================
Live check of the service-map Cypher (FR-13, FR-29) against the real Neo4j
database. The in-memory FakeServiceGraph used elsewhere only imitates these
queries.

Skipped unless ``AEGIS_RUN_INTEGRATION=1``. Every node it creates has an id
starting with ``it-<run>-`` and those nodes (only those) are removed at the
end, so the real service map is left as it was.

    $env:AEGIS_RUN_INTEGRATION=1; python -m pytest tests/test_integration_service_map.py -v
"""

from __future__ import annotations

import os
import time
import uuid

import pytest
from dotenv import load_dotenv

load_dotenv()

pytestmark = pytest.mark.skipif(
    os.environ.get("AEGIS_RUN_INTEGRATION") != "1",
    reason="set AEGIS_RUN_INTEGRATION=1 to run live Neo4j tests",
)

RUN = f"it-{uuid.uuid4().hex[:8]}-"


def sid(name: str) -> str:
    return RUN + name


@pytest.fixture(scope="module")
def graph():
    from database.neo4j_client import Neo4jClient

    client = Neo4jClient()
    yield client
    with client.driver.session() as s:  # remove only this run's nodes
        s.run("MATCH (n) WHERE n.id STARTS WITH $p OR n.name STARTS WITH $p DETACH DELETE n", p=RUN)
    client.close()


@pytest.fixture(scope="module")
def mapped(graph):
    """gateway -> checkout -> payment -> db(external); order -> payment; lonely"""
    for name in ("gateway", "checkout", "order", "payment", "lonely"):
        graph.create_service(sid(name), name.title(), "service", None)
    graph.set_dependency(sid("gateway"), sid("checkout"), "service", "HTTP")
    graph.set_dependency(sid("checkout"), sid("payment"), "service", "gRPC")
    graph.set_dependency(sid("order"), sid("payment"), "service", "gRPC")
    graph.set_dependency(sid("payment"), sid("db"), "external", "TCP", "database")
    return graph


def test_service_crud(mapped):
    from database.neo4j_client import ServiceExistsError

    svc = mapped.get_service(sid("payment"))
    assert svc["name"] == "Payment" and svc["created_at"] and svc["retired_at"] is None
    with pytest.raises(ServiceExistsError):
        mapped.create_service(sid("payment"), "dup")
    assert mapped.update_service(sid("lonely"), {"tier": "bronze"})["tier"] == "bronze"
    assert sid("payment") in {s["id"] for s in mapped.list_services()}


def test_dependencies_dependents_and_existing_queries(mapped):
    deps = mapped.get_dependencies(sid("payment"))
    assert [(d["id"], d["kind"], d["type"]) for d in deps] == [(sid("db"), "external", "database")]
    assert {d["id"] for d in mapped.get_dependents(sid("payment"))} == {sid("checkout"), sid("order")}
    assert {b["id"]: b["hops"] for b in mapped.get_blast_radius(sid("payment"))} == {
        sid("checkout"): 1, sid("order"): 1, sid("gateway"): 2}
    assert {c["name"] for c in mapped.get_service_context(sid("payment"))} == {sid("db")}


def test_shared_dependencies(mapped):
    found = mapped.find_shared_dependencies(sid("checkout"), [sid("order"), sid("payment"), sid("lonely"),
                                                             sid("does-not-exist")], max_hops=2)
    assert set(found) == {sid("order"), sid("payment")}
    assert found[sid("order")]["id"] == sid("payment")
    assert (found[sid("order")]["hops_a"], found[sid("order")]["hops_b"]) == (1, 1)
    assert found[sid("payment")]["id"] == sid("payment")
    assert (found[sid("payment")]["hops_a"], found[sid("payment")]["hops_b"]) == (1, 0)
    # gateway -> checkout -> payment is 2 links; with max 1 the gateway only reaches checkout
    assert mapped.find_shared_dependencies(sid("gateway"), [sid("order")], max_hops=1) == {}
    assert mapped.find_shared_dependencies(sid("gateway"), [sid("order")], max_hops=2)[sid("order")]["id"] == sid("payment")


def test_unchanged_updated_and_history(mapped):
    assert mapped.set_dependency(sid("order"), sid("payment"), "service", "gRPC") == "unchanged"
    assert mapped.set_dependency(sid("order"), sid("payment"), "service", "HTTP") == "updated"
    history = mapped.get_dependency_history(sid("order"))
    assert [(h["protocol"], h["valid_to"] is None) for h in history] == [("HTTP", True), ("gRPC", False)]


def test_remove_and_time_travel(mapped):
    # Link dates are stamped by the Neo4j server, so "before" must come from the
    # server's clock too (this machine's clock can differ by a fraction of a second).
    with mapped.driver.session() as s:
        before = s.run("RETURN toString(datetime()) AS now").single()["now"]
    time.sleep(0.05)
    assert mapped.remove_dependency(sid("gateway"), sid("checkout")) is True
    assert mapped.remove_dependency(sid("gateway"), sid("checkout")) is False
    assert mapped.get_dependencies(sid("gateway")) == []
    assert [d["id"] for d in mapped.get_dependencies(sid("gateway"), at=before)] == [sid("checkout")]


def test_retire(mapped):
    from database.neo4j_client import InvalidDependencyError, ServiceNotFoundError

    with pytest.raises(InvalidDependencyError):
        mapped.set_dependency(sid("lonely"), sid("lonely"))
    mapped.set_dependency(sid("lonely"), sid("payment"))
    closed = mapped.retire_service(sid("payment"))
    assert closed >= 3  # checkout->payment, order->payment, payment->db, lonely->payment
    assert mapped.get_service(sid("payment"))["retired_at"]
    assert sid("payment") not in {s["id"] for s in mapped.list_services()}
    assert sid("payment") in {s["id"] for s in mapped.list_services(include_retired=True)}
    assert mapped.get_dependencies(sid("checkout")) == []
    assert mapped.find_shared_dependencies(sid("checkout"), [sid("order")]) == {}
    with pytest.raises(ServiceNotFoundError):
        mapped.retire_service(sid("payment"))
    with pytest.raises(ServiceNotFoundError):
        mapped.set_dependency(sid("checkout"), sid("payment"))
