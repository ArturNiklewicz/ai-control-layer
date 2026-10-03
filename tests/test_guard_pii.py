"""Deterministic + semantic PII detection, masking, pseudonym round-trip."""

import json

import pytest

from src.guard.pii import (
    SemanticError,
    anonymize,
    detect,
    pseudonymize,
    restore,
    semantic_spans,
)
from src.result import Err, Ok


@pytest.mark.parametrize(
    "text, kind",
    [
        ("PESEL 44051401359", "PESEL"),
        ("PESEL 02270803624", "PESEL"),  # born 2002: month +20
        ("NIP 526-104-08-28", "NIP"),
        ("NIP 5261040828", "NIP"),
        ("REGON 123456785", "REGON"),
        ("PL61 1090 1014 0000 0712 1981 2874", "IBAN"),
        ("4111 1111 1111 1111", "CARD"),
        ("dowód ABA300000", "ID_CARD"),
        ("jan.k@example.com", "EMAIL"),
        ("tel +48 600 700 800", "PHONE"),
        ("key AKIAIOSFODNN7EXAMPLE", "SECRET"),
        ("token = 'abcd1234efgh5678'", "SECRET"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIx\n-----END RSA PRIVATE KEY-----", "SECRET"),
    ],
)
def test_detects(text, kind):
    assert [s.kind for s in detect(text)] == [kind]


@pytest.mark.parametrize(
    "text, kind",
    [
        ("PESEL 44051401358", "PESEL"),  # bad checksums
        ("NIP 526-104-08-29", "NIP"),
        ("REGON 123456789", "REGON"),
        ("PL61 1090 1014 0000 0712 1981 2875", "IBAN"),
        ("4111 1111 1111 1112", "CARD"),
        ("ABA300001", "ID_CARD"),
        ("token = 'short'", "SECRET"),
    ],
)
def test_bad_checksum_is_not_that_kind(text, kind):
    assert kind not in {s.kind for s in detect(text)}


def test_ordinary_numbers_are_not_pii():
    assert detect("zamówienie 2026-10-03, wersja 1.2.3, kwota 1500 zł, 42 sztuki") == []


def test_secret_span_keeps_key_name_readable():
    t = 'api_key = "zx81Kq9LmP0aB7cD"'
    assert anonymize(t, detect(t)) == 'api_key = "[SECRET]"'


def test_pseudonyms_are_consistent_and_reversible():
    t = "A 44051401359, B 44051401359, mail X@Ex.com i x@ex.com"
    masked, vault = pseudonymize(t, detect(t), {})
    assert masked == "A [PESEL_1], B [PESEL_1], mail [EMAIL_1] i [EMAIL_1]"
    assert restore(masked, vault) == "A 44051401359, B 44051401359, mail x@ex.com i x@ex.com"
    again, vault2 = pseudonymize("C 02270803624", detect("C 02270803624"), vault)
    assert again == "C [PESEL_2]" and vault2["PESEL_1"] == "44051401359"


def test_restore_leaves_unknown_tokens():
    assert restore("[OSOBA_9] i [PESEL_1]", {"PESEL_1": "x"}) == "[OSOBA_9] i x"


# --- semantic detector with a fake local model ---

DOC = "Rozmawiałam z Anną Nowak. Anna Nowak mieszka przy ul. Długiej 5."


def fake(entities):
    calls = []

    def complete(messages, **kw):
        calls.append((messages, kw))
        return Ok(json.dumps({"entities": entities}))

    return complete, calls


def test_semantic_maps_inflections_to_one_canonical():
    complete, calls = fake([
        {"type": "PERSON", "text": "Anna Nowak", "canonical": "Anna Nowak"},
        {"type": "ADDRESS", "text": "ul. Długiej 5", "canonical": "ul. Długa 5"},
    ])  # fmt: skip
    r = semantic_spans(DOC, complete)
    assert isinstance(r, Ok)
    masked, vault = pseudonymize(DOC, r.value, {})
    assert masked == "Rozmawiałam z [OSOBA_1]. [OSOBA_1] mieszka przy [ADRES_1]."
    assert vault == {"OSOBA_1": "Anna Nowak", "ADRES_1": "ul. Długa 5"}
    assert "<document>" in calls[0][0][1]["content"]  # document passed as data
    assert "response_format" in calls[0][1]


def test_semantic_ignores_entities_not_in_text():
    complete, _ = fake([{"type": "PERSON", "text": "Kowalski", "canonical": "Jan Kowalski"}])
    assert semantic_spans(DOC, complete) == Ok([])


@pytest.mark.parametrize("raw", ["not json", '{"entities": [{"type": "PERSON"}]}', "[]"])
def test_semantic_malformed_output_is_err(raw):
    r = semantic_spans(DOC, lambda m, **kw: Ok(raw))
    assert isinstance(r, Err) and isinstance(r.error, SemanticError)


def test_semantic_provider_error_propagates():
    assert semantic_spans(DOC, lambda m, **kw: Err("down")) == Err("down")


def test_semantic_recovers_misquoted_inflection():
    # real qwen3 output: quote mixes nominative first name with instrumental surname
    doc = "Pilotaż prowadziła wraz z wolontariuszem Pawłem Kaczmarkiem."
    complete, _ = fake([{"type": "PERSON", "text": "Paweł Kaczmarkiem", "canonical": "Paweł Kaczmarek"}])
    r = semantic_spans(doc, complete)
    assert isinstance(r, Ok)
    assert pseudonymize(doc, r.value, {})[0] == "Pilotaż prowadziła wraz z wolontariuszem [OSOBA_1]."
