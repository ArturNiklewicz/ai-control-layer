"""Consent + PII pipeline on real documents: pty login, sops vault, guard CLI, local LLM NER."""

import json
import re

import pytest



pytestmark = [pytest.mark.integration, pytest.mark.pii]

ORIGINALS = {  # values that must never survive in a scrubbed document
    "mops_notatka.txt": ["47030502913", "01241109835", "512 334 876", "t.zielinski@example.com",
                         "PL61 1090 1014 0000 0712 1981 2874", "ABC523456"],
    "beneficjenci.csv": ["52061204170", "88112503824", "47030502913", "600 700 800", "jan.k@example.com"],
}  # fmt: skip
NAMES = {  # only the LLM can find these
    "mops_notatka.txt": ["Halina", "Wiśniewsk", "Tomasz", "Zielińsk", "Marek Lewandowski", "ul. Szlak 41"],
    "wniosek_grantowy.txt": ["Katarzyna Mazur", "Kaczmar", "ul. Lubicz 17"],
}  # fmt: skip


# --- consent: authentication before any transformation ---


@pytest.mark.consent
@pytest.mark.negative
def test_no_login_means_no_transformation(repo, say, age_key):
    say.title("Brak zgody → dokument nie zostaje przetworzony")
    say.step("pseudonymize docs/mops_notatka.txt bez wcześniejszego login")
    r = repo.cli("pseudonymize", str(repo.path / "docs/mops_notatka.txt"), "-o", str(repo.path / "out.txt"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "no valid consent" in r.stderr
    assert not (repo.path / "out.txt").exists()


@pytest.mark.consent
@pytest.mark.negative
def test_agent_cannot_log_in_without_a_terminal(repo, say, age_key):
    say.title("Agent (bez TTY) próbuje sam wyrazić zgodę")
    r = repo.cli("login")
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "interactive terminal" in r.stderr
    assert not (repo.path / ".guard/consent.sops.json").exists()


@pytest.mark.consent
@pytest.mark.negative
def test_human_declines(repo, say, age_key):
    say.title("Człowiek odmawia zgody w terminalu")
    code, out = repo.login(answer="n")
    say.show("terminal", out)
    assert code == 1 and not (repo.path / ".guard/consent.sops.json").exists()
    say.blocked("brak zgody, nic nie zapisano")


@pytest.mark.consent
@pytest.mark.vault
@pytest.mark.positive
def test_human_login_creates_sealed_grant(repo, say, age_key):
    say.title("Logowanie: TTY + dowód klucza age + 'tak' → zaszyfrowana zgoda")
    code, out = repo.login("t")
    say.show("terminal", out)
    assert code == 0 and "klucz age zweryfikowany" in out
    grant = (repo.path / ".guard/consent.sops.json").read_text()
    say.step("plik zgody na dysku")
    say.show("consent.sops.json", grant, limit=300)
    assert '"user": "ENC[' in grant and "sops" in grant
    say.ok("zgoda zaszyfrowana sops+age; audyt:")
    say.show("audit", json.dumps([e for e in repo.audit() if e.get("event") == "consent"], ensure_ascii=False))


@pytest.mark.consent
@pytest.mark.negative
def test_tampered_grant_is_no_grant(repo, say, age_key):
    say.title("Agent podmienia plik zgody → zgoda nieważna")
    assert repo.login("t")[0] == 0
    p = repo.path / ".guard/consent.sops.json"
    sealed = json.loads(p.read_text())
    sealed["expires_at"] = re.sub(r"data:[^,]+", "data:MjA5OS0wMS0wMVQwMDowMDowMCswMDowMA==", sealed["expires_at"])
    p.write_text(json.dumps(sealed))
    say.step("expires_at nadpisane na 2099, MAC sops nie pasuje")
    r = repo.cli("anonymize", str(repo.path / "docs/beneficjenci.csv"), "-o", str(repo.path / "o.csv"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "no valid consent" in r.stderr


# --- deterministic PII (no model) ---


@pytest.mark.consent
@pytest.mark.vault
@pytest.mark.positive
def test_pseudonymize_round_trip_on_csv(repo, say, age_key):
    say.title("Pseudonimizacja CSV beneficjentów → sejf → odtworzenie")
    assert repo.login("t")[0] == 0
    src, out = repo.path / "docs/beneficjenci.csv", repo.path / "clean/beneficjenci.csv"
    say.show("wejście", src.read_text())
    r = repo.cli("pseudonymize", str(src), "-o", str(out))
    say.step(r.stdout.strip())
    clean = out.read_text()
    say.show("wynik", clean)
    leaked = [v for v in ORIGINALS["beneficjenci.csv"] if v in clean]
    assert r.returncode == 0 and not leaked, leaked
    assert clean.count("[PESEL_3]") == 1 and "[PESEL_1]" in clean  # 3 distinct people
    vault = (repo.path / ".guard/vault.sops.json").read_text()
    assert "52061204170" not in vault
    say.ok("sejf na dysku zaszyfrowany (brak PESEL w pliku)")
    r = repo.cli("restore", str(out))
    say.show("restore (tylko właściciel klucza)", r.stdout)
    assert "52061204170" in r.stdout and "88112503824" in r.stdout


@pytest.mark.negative
def test_secrets_block_the_whole_document(repo, say, age_key):
    say.title("Dokument z sekretami → polityka 'block', nic nie wychodzi")
    assert repo.login("t")[0] == 0
    src = repo.path / "docs/konfiguracja_z_sekretem.env.txt"
    r = repo.cli("anonymize", str(src), "-o", str(repo.path / "o.txt"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "SECRET" in r.stderr and not (repo.path / "o.txt").exists()
    assert any(e.get("rule") == "pii-block" for e in repo.audit())


@pytest.mark.positive
def test_public_report_passes_unchanged(repo, say, age_key):
    say.title("Raport publiczny bez danych osobowych → bez zmian")
    assert repo.login("t")[0] == 0
    src, out = repo.path / "docs/raport_publiczny.txt", repo.path / "o.txt"
    r = repo.cli("anonymize", str(src), "-o", str(out))
    say.ok(r.stdout.strip())
    assert out.read_text() == src.read_text()


@pytest.mark.policy
@pytest.mark.positive
def test_strictness_change_applies_immediately(repo, say, age_key):
    say.title("Zmiana surowości w policy.toml działa od następnego wywołania")
    assert repo.login("t")[0] == 0
    src = repo.path / "docs/beneficjenci.csv"
    r = repo.cli("pseudonymize", str(src), "-o", str(repo.path / "a.csv"))
    say.ok(f"PESEL=pseudonymize → {r.stdout.strip()}")
    repo.edit_policy("CARD = \"block\"", "CARD = \"block\"\nPESEL = \"block\"")
    say.step("policy.toml: PESEL = \"block\"")
    r = repo.cli("pseudonymize", str(src), "-o", str(repo.path / "b.csv"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "PESEL" in r.stderr


# --- hybrid: local LLM finds names and addresses ---


@pytest.mark.live
@pytest.mark.positive
@pytest.mark.parametrize("doc", ["mops_notatka.txt", "wniosek_grantowy.txt"])
def test_llm_ner_pseudonymizes_names_and_addresses(live_repo, say, age_key, doc):
    say.title(f"Hybryda regex + LLM (DGX) na {doc}")
    assert live_repo.login("t")[0] == 0
    src, out = live_repo.path / "docs" / doc, live_repo.path / "clean" / doc
    say.show("wejście", src.read_text())
    say.step("guard pseudonymize (NER: qwen3-35b przez tailnet)")
    r = live_repo.cli("pseudonymize", str(src), "-o", str(out))
    assert r.returncode == 0, r.stderr
    say.ok(r.stdout.strip())
    clean = out.read_text()
    say.show("wynik", clean)
    leaked = [v for v in NAMES[doc] + ORIGINALS.get(doc, []) if v in clean]
    assert not leaked, f"leaked: {leaked}"
    assert "[OSOBA_1]" in clean and "[ADRES_1]" in clean
    restored = live_repo.cli("restore", str(out)).stdout
    say.show("restore", restored)
    assert "[OSOBA_" not in restored


@pytest.mark.live
@pytest.mark.negative
def test_llm_never_called_on_public_host(repo, say, age_key):
    say.title("NER na publicznym hoście → odmowa, PII nie wysłane")
    repo.edit_policy("semantic = false", "semantic = true")
    repo.edit_policy('base_url = "http://100.117.237.101:8006/v1"', 'base_url = "https://api.openai.com/v1"')
    r = repo.cli("scan", str(repo.path / "docs/mops_notatka.txt"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "not private" in r.stderr


@pytest.mark.negative
def test_llm_down_fails_closed(repo, say):
    say.title("Lokalny LLM niedostępny → fail-closed")
    repo.edit_policy("semantic = false", "semantic = true")
    repo.edit_policy('base_url = "http://100.117.237.101:8006/v1"', 'base_url = "http://127.0.0.1:9/v1"')
    r = repo.cli("scan", str(repo.path / "docs/mops_notatka.txt"))
    say.blocked(r.stderr.strip())
    assert r.returncode == 1 and "fail_closed" in r.stderr

