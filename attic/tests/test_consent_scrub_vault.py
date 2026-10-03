"""Moved from tests/test_guard_controls.py with consent.py / scrub.py / vault.py (see attic/README.md)."""

def test_consent_scope_and_expiry():
    g = grant("artur", frozenset({"anonymize", "pseudonymize", "rm -rf"}), NOW, 8, "tty+age-key")
    assert g.actions == {"anonymize", "pseudonymize"}  # unknown actions dropped
    assert allows(g, "pseudonymize", NOW + timedelta(hours=7))
    assert not allows(g, "pseudonymize", NOW + timedelta(hours=8))
    assert not allows(g, "pseudonymize", NOW - timedelta(seconds=1))
    assert not allows(None, "anonymize", NOW)
    assert from_json(to_json(g, "n"), "n", 8) == g
    assert from_json({"user": "x"}, "n", 8) is None


# --- scrub: block vs redact vs pseudonymize, consent gate ---


def test_scrub_applies_per_kind_actions():
    r = scrub(DOC, detect(DOC), policy(), {}, lambda a: True)
    assert isinstance(r, Ok) and r.value.text == "Klient [PESEL_1], mail [EMAIL]"
    assert r.value.vault == {"PESEL_1": "44051401359"} and r.value.counts == {"PESEL": 1, "EMAIL": 1}


def test_scrub_without_consent_is_fail_closed():
    r = scrub(DOC, detect(DOC), policy(), {}, lambda a: False)
    assert r == Err(NoConsent(("anonymize", "pseudonymize"), ("EMAIL", "PESEL")))


def test_scrub_blocks_before_asking_consent():
    t = DOC + " key AKIAIOSFODNN7EXAMPLE"
    assert scrub(t, detect(t), policy(), {}, lambda a: False) == Err(Blocked(("SECRET",)))


def test_scrub_off_and_strictness_from_policy():
    loose = policy(pii__default="off", pii__kinds={"EMAIL": "off"})
    assert scrub(DOC, detect(DOC), loose, {}, lambda a: False).value.text == DOC  # type: ignore[union-attr]
    strict = policy(pii__kinds={"PESEL": "block"})
    assert scrub(DOC, detect(DOC), strict, {}, lambda a: True) == Err(Blocked(("PESEL",)))


def test_anonymize_mode_never_mints_pseudonyms():
    r = scrub(DOC, detect(DOC), as_anonymize(policy()), {}, lambda a: True)
    assert r.value.text == "Klient [PESEL], mail [EMAIL]" and r.value.vault == {}  # type: ignore[union-attr]


# --- injection / historical exploit feed ---

def test_vault_maps_sops_failure_to_err(tmp_path):
    (tmp_path / "v.json").write_text("{}")
    failed = lambda *a, **k: subprocess.CompletedProcess(a, 1, "", "Failed to get the data key")  # noqa: E731
    assert load_sealed(tmp_path / "v.json", run=failed) == Err(load_sealed(tmp_path / "v.json", run=failed).error)  # type: ignore[union-attr]
    assert isinstance(save_sealed(tmp_path / "v.json", {}, "not-a-key"), Err)


def test_missing_vault_is_empty(tmp_path):
    assert load_sealed(tmp_path / "nope.json") == Ok({})


@pytest.mark.skipif(not shutil.which("sops") or not (Path.home() / ".config/sops/age/keys.txt").exists(), reason="sops/age key absent")
def test_vault_roundtrip_is_encrypted_at_rest(tmp_path):
    p = tmp_path / "vault.sops.json"
    assert save_sealed(p, {"OSOBA_1": "Jan Kowalski"}, policy().age_recipient) == Ok(p)
    assert "Jan Kowalski" not in p.read_text()
    assert load_sealed(p) == Ok({"OSOBA_1": "Jan Kowalski"})
    tampered = json.loads(p.read_text())
    tampered["OSOBA_1"] = tampered["OSOBA_1"].replace("data:", "data:A", 1)
    p.write_text(json.dumps(tampered))
    assert isinstance(load_sealed(p), Err)  # MAC check: tampering detected


def test_grant_needs_the_host_nonce():  # finding 1, 4
    raw = to_json(G, "secret")
    assert from_json(raw, "secret", 8) == G
    assert from_json(raw, "", 8) is None  # logged out: no host nonce, replayed copy is dead
    assert from_json(raw, "other", 8) is None  # forged / copied from an older login
    assert from_json({k: v for k, v in raw.items() if k != "nonce"}, "secret", 8) is None


def test_grant_lifetime_is_capped_by_policy():  # finding 1
    forged = to_json(G, "n") | {"expires_at": datetime(2099, 1, 1, tzinfo=UTC).isoformat()}
    assert from_json(forged, "n", 8) is None
    future = grant("a", frozenset({"anonymize"}), NOW + timedelta(days=1), 8, "x")
    assert not allows(future, "anonymize", NOW)


def test_save_sealed_refuses_symlinks(tmp_path):  # finding 3
    victim = tmp_path / "zshrc"
    victim.write_text("keep")
    (tmp_path / "v.json").symlink_to(victim)
    assert isinstance(save_sealed(tmp_path / "v.json", {}, "age1x", sealed), Err)
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    assert isinstance(save_sealed(tmp_path / "link" / "v.json", {}, "age1x", sealed), Err)
    assert victim.read_text() == "keep"


def test_save_sealed_ignores_planted_tmp_name(tmp_path):  # finding 3
    victim = tmp_path / "zshrc"
    victim.write_text("keep")
    (tmp_path / "v.tmp").symlink_to(victim)
    assert save_sealed(tmp_path / "v.json", {}, "age1x", sealed) == Ok(tmp_path / "v.json")
    assert victim.read_text() == "keep"


def test_vault_swapped_by_agent_is_refused(tmp_path):  # finding 2
    v, pin = tmp_path / "vault.sops.json", tmp_path / "host" / "vault-hash"
    assert save_pinned(v, {}, "age1x", pin, sealed) == Ok(v)
    assert load_pinned(v, pin, sealed) == Ok({"OSOBA_1": "x"})
    v.write_text('{"poison": 1}')
    assert isinstance(load_pinned(v, pin, sealed), Err)
    pin.unlink()
    assert isinstance(load_pinned(v, pin, sealed), Err)  # no pin == not ours
    assert load_pinned(tmp_path / "none.json", pin, sealed) == Ok({})


