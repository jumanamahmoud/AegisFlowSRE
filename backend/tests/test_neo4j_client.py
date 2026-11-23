"""
Unit tests for backend/database/neo4j_client.py

Covers Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6
"""

import pytest
from unittest.mock import MagicMock, patch

import database.neo4j_client as neo4j_client_module
from database.neo4j_client import Neo4jClient


@pytest.fixture(autouse=True)
def reset_singleton(monkeypatch):
    """Reset the module-level singleton before every test to avoid cross-test pollution."""
    monkeypatch.setattr("database.neo4j_client._client", None)


# ---------------------------------------------------------------------------
# 1. __init__ reads env vars correctly
# ---------------------------------------------------------------------------

def test_init_reads_env_vars(neo4j_env, mock_neo4j_driver):
    """Neo4jClient() reads all three env vars and passes them to GraphDatabase.driver.

    Requirements: 1.1
    """
    client = Neo4jClient()

    mock_neo4j_driver.assert_called_once_with(
        "neo4j://localhost:7687",
        auth=("neo4j", "testpassword"),
    )
    client.close()


# ---------------------------------------------------------------------------
# 2–4. __init__ raises RuntimeError for each missing env var
# ---------------------------------------------------------------------------

def test_init_raises_on_missing_neo4j_uri(neo4j_env, mock_neo4j_driver, monkeypatch):
    """Missing NEO4J_URI raises RuntimeError mentioning 'NEO4J_URI'.

    Requirements: 1.2
    """
    monkeypatch.delenv("NEO4J_URI")

    with pytest.raises(RuntimeError, match="NEO4J_URI"):
        Neo4jClient()

    # Driver must NOT have been constructed
    mock_neo4j_driver.assert_not_called()


def test_init_raises_on_missing_neo4j_user(neo4j_env, mock_neo4j_driver, monkeypatch):
    """Missing NEO4J_USER raises RuntimeError mentioning 'NEO4J_USER'.

    Requirements: 1.2
    """
    monkeypatch.delenv("NEO4J_USER")

    with pytest.raises(RuntimeError, match="NEO4J_USER"):
        Neo4jClient()

    mock_neo4j_driver.assert_not_called()


def test_init_raises_on_missing_neo4j_password(neo4j_env, mock_neo4j_driver, monkeypatch):
    """Missing NEO4J_PASSWORD raises RuntimeError mentioning 'NEO4J_PASSWORD'.

    Requirements: 1.2
    """
    monkeypatch.delenv("NEO4J_PASSWORD")

    with pytest.raises(RuntimeError, match="NEO4J_PASSWORD"):
        Neo4jClient()

    mock_neo4j_driver.assert_not_called()


# ---------------------------------------------------------------------------
# 5. verify_connectivity() returns True on success
# ---------------------------------------------------------------------------

def test_verify_connectivity_returns_true(neo4j_env, mock_neo4j_driver):
    """verify_connectivity() returns True when the driver confirms connectivity.

    Requirements: 1.3
    """
    mock_driver_instance = MagicMock()
    mock_driver_instance.verify_connectivity.return_value = None  # driver returns None on success
    mock_neo4j_driver.return_value = mock_driver_instance

    client = Neo4jClient()
    result = client.verify_connectivity()

    assert result is True
    mock_driver_instance.verify_connectivity.assert_called_once()
    client.close()


# ---------------------------------------------------------------------------
# 6. verify_connectivity() wraps driver exception as ConnectionError
# ---------------------------------------------------------------------------

def test_verify_connectivity_raises_connection_error(neo4j_env, mock_neo4j_driver):
    """verify_connectivity() raises ConnectionError when the driver raises.

    The original cause message must appear in the ConnectionError message.
    Requirements: 1.4
    """
    mock_driver_instance = MagicMock()
    mock_driver_instance.verify_connectivity.side_effect = Exception("timeout")
    mock_neo4j_driver.return_value = mock_driver_instance

    client = Neo4jClient()

    with pytest.raises(ConnectionError) as exc_info:
        client.verify_connectivity()

    assert "timeout" in str(exc_info.value)
    client.close()


# ---------------------------------------------------------------------------
# 7. close() delegates to driver.close()
# ---------------------------------------------------------------------------

def test_close_calls_driver_close(neo4j_env, mock_neo4j_driver):
    """close() must call driver.close() exactly once.

    Requirements: 1.6
    """
    mock_driver_instance = MagicMock()
    mock_neo4j_driver.return_value = mock_driver_instance

    client = Neo4jClient()
    client.close()

    mock_driver_instance.close.assert_called_once()


# ---------------------------------------------------------------------------
# 8. Async context manager calls close() on exit
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_async_context_manager_calls_close(neo4j_env, mock_neo4j_driver):
    """Async context manager protocol calls driver.close() on exit.

    Requirements: 1.5
    """
    mock_driver_instance = MagicMock()
    mock_neo4j_driver.return_value = mock_driver_instance

    async with Neo4jClient() as client:
        # driver.close() must NOT be called while still inside the context
        mock_driver_instance.close.assert_not_called()

    # driver.close() must have been called after exiting the context
    mock_driver_instance.close.assert_called_once()
