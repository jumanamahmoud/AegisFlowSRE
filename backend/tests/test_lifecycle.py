"""
backend/tests/test_lifecycle.py
================================
Incident lifecycle rules (FR-15): every allowed move passes, every other
move — including staying in place — is rejected.
"""

from __future__ import annotations

import itertools

import pytest

from models.incident import (
    ALLOWED_TRANSITIONS,
    AuditEventType,
    IncidentStatus,
    InvalidTransitionError,
    validate_transition,
)

S = IncidentStatus

EXPECTED_ALLOWED = {
    (S.OPEN, S.ACKNOWLEDGED),
    (S.OPEN, S.RESOLVED),
    (S.ACKNOWLEDGED, S.MITIGATING),
    (S.ACKNOWLEDGED, S.RESOLVED),
    (S.MITIGATING, S.RESOLVED),
    (S.RESOLVED, S.CLOSED),
    (S.RESOLVED, S.OPEN),
}


def test_status_values_match_database_enum():
    assert [s.value for s in S] == ["open", "acknowledged", "mitigating", "resolved", "closed"]


def test_every_status_has_a_transition_entry():
    assert set(ALLOWED_TRANSITIONS) == set(S)


@pytest.mark.parametrize("current,target", sorted(EXPECTED_ALLOWED))
def test_allowed_transitions_pass(current, target):
    validate_transition(current, target)  # no exception


@pytest.mark.parametrize(
    "current,target",
    [p for p in itertools.product(S, S) if p not in EXPECTED_ALLOWED],
)
def test_all_other_transitions_rejected(current, target):
    with pytest.raises(InvalidTransitionError):
        validate_transition(current, target)


def test_closed_is_terminal():
    assert ALLOWED_TRANSITIONS[S.CLOSED] == frozenset()
    with pytest.raises(InvalidTransitionError, match="terminal"):
        validate_transition("closed", "open")


def test_accepts_plain_strings():
    validate_transition("open", "acknowledged")


def test_unknown_status_string_raises_value_error():
    with pytest.raises(ValueError):
        validate_transition("open", "on-fire")


def test_error_message_lists_allowed_targets():
    with pytest.raises(InvalidTransitionError) as exc:
        validate_transition(S.OPEN, S.CLOSED)
    assert "acknowledged" in str(exc.value) and "resolved" in str(exc.value)
    assert exc.value.current is S.OPEN and exc.value.target is S.CLOSED


def test_audit_event_types_are_namespaced():
    assert all("." in e.value for e in AuditEventType)
