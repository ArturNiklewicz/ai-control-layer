"""Generate the labelled PL PII eval set: fictional people, checksum-valid IDs, exact gold spans.

`uv run python eval/gen_pii.py` -> eval/datasets/pii_pl.jsonl (deterministic, seeded).
Hard negatives (invalid checksums, order numbers, amounts, dates) carry no gold spans.
"""

import json
import random
import string
from pathlib import Path

R = random.Random(20261003)

PEOPLE = [  # nominative, genitive, instrumental
    ("Jan Kowalski", "Jana Kowalskiego", "Janem Kowalskim"),
    ("Anna Nowak", "Anny Nowak", "Anną Nowak"),
    ("Paweł Kaczmarek", "Pawła Kaczmarka", "Pawłem Kaczmarkiem"),
    ("Katarzyna Wiśniewska", "Katarzyny Wiśniewskiej", "Katarzyną Wiśniewską"),
    ("Tomasz Zieliński", "Tomasza Zielińskiego", "Tomaszem Zielińskim"),
    ("Magdalena Lewandowska", "Magdaleny Lewandowskiej", "Magdaleną Lewandowską"),
    ("Piotr Wójcik", "Piotra Wójcika", "Piotrem Wójcikiem"),
    ("Agnieszka Kamińska", "Agnieszki Kamińskiej", "Agnieszką Kamińską"),
    ("Michał Szymański", "Michała Szymańskiego", "Michałem Szymańskim"),
    ("Joanna Dąbrowska", "Joanny Dąbrowskiej", "Joanną Dąbrowską"),
    ("Krzysztof Jankowski", "Krzysztofa Jankowskiego", "Krzysztofem Jankowskim"),
    ("Ewa Mazur", "Ewy Mazur", "Ewą Mazur"),
]
STREETS = [
    "Lipowa",
    "Kwiatowa",
    "Polna",
    "Słoneczna",
    "Leśna",
    "Ogrodowa",
    "Mickiewicza",
]
CITIES = [
    ("00-950", "Warszawa"),
    ("30-001", "Kraków"),
    ("80-180", "Gdańsk"),
    ("50-077", "Wrocław"),
]


def num(n: int) -> str:
    return "".join(R.choice(string.digits) for _ in range(n))


def pesel() -> str:
    y, m, d = R.randint(1950, 2009), R.randint(1, 12), R.randint(1, 28)
    mm = m + (20 if y >= 2000 else 0)
    s = f"{y % 100:02d}{mm:02d}{d:02d}{num(4)}"
    w = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    return s + str((10 - sum(int(a) * b for a, b in zip(s, w)) % 10) % 10)


def nip() -> str:
    while True:
        s = num(9)
        c = sum(int(a) * b for a, b in zip(s, (6, 5, 7, 2, 3, 4, 5, 6, 7))) % 11
        if c != 10:
            d = s + str(c)
            return f"{d[:3]}-{d[3:6]}-{d[6:8]}-{d[8:]}"


def regon() -> str:
    s = num(8)
    return s + str(
        sum(int(a) * b for a, b in zip(s, (8, 9, 2, 3, 4, 5, 6, 7))) % 11 % 10
    )


def iban() -> str:
    bban = num(24)
    check = 98 - int("".join(str(int(c, 36)) for c in bban + "PL00")) % 97
    raw = f"PL{check:02d}{bban}"
    return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def card() -> str:
    s = "4" + num(14)
    total = sum(
        x if i % 2 else (x * 2 - 9 if x > 4 else x * 2)
        for i, x in enumerate(int(c) for c in reversed(s))
    )
    d = s + str((10 - total % 10) % 10)
    return " ".join(d[i : i + 4] for i in range(0, 16, 4))


def id_card() -> str:
    letters = "".join(R.choice(string.ascii_uppercase) for _ in range(3))
    rest = num(5)
    w = (7, 3, 1, 9, 7, 3, 1, 7, 3)
    r = sum(int(c, 36) * k for c, k in zip(letters + "0" + rest, w))
    return f"{letters}{r % 10}{rest}"


def phone() -> str:
    return R.choice(["+48 ", ""]) + f"{R.randint(5, 8)}{num(2)} {num(3)} {num(3)}"


def email(nom: str) -> str:
    first, last = nom.lower().split()
    tr = str.maketrans("ąćęłńóśźż", "acelnoszz")
    return f"{first.translate(tr)}.{last.translate(tr)}@{R.choice(['example.pl', 'poczta.example.com'])}"


def secret() -> str:
    return R.choice(
        [
            "sk-"
            + "".join(
                R.choice(string.ascii_letters + string.digits) for _ in range(32)
            ),
            "AKIA"
            + "".join(
                R.choice(string.ascii_uppercase + string.digits) for _ in range(16)
            ),
        ]
    )


def address() -> str:
    code, city = R.choice(CITIES)
    return (
        f"ul. {R.choice(STREETS)} {R.randint(1, 120)}/{R.randint(1, 40)}, {code} {city}"
    )


# {KIND} or {KIND:form} placeholders; every placeholder becomes a gold span
TEMPLATES = [
    "Wnioskodawca {PERSON:nom}, PESEL {PESEL}, zam. {ADDRESS}, tel. {PHONE}.",
    "Decyzja dotyczy {PERSON:gen} (nr dowodu {ID_CARD}). Kontakt: {EMAIL}.",
    "Przelew na rachunek {IBAN} zlecił {PERSON:nom}. Firma: NIP {NIP}, REGON {REGON}.",
    "Rozmowę z {PERSON:ins} przeprowadzono w dniu 12.03.2026. Adres: {ADDRESS}.",
    "Płatność kartą {CARD} na kwotę 1 250,00 zł. Klient: {PERSON:nom}, {EMAIL}.",
    "config:\n  api_base: https://api.example.com\n  key: {SECRET}\n",
    "Beneficjent {PERSON:nom} (PESEL {PESEL}) mieszka pod adresem {ADDRESS}. "
    "Opiekun {PERSON2:nom} prosi o kontakt pod numerem {PHONE}.",
    "Notatka MOPS: u {PERSON:gen} stwierdzono zadłużenie. Konto {IBAN}. Tel. {PHONE}.",
]
NEGATIVES = [
    "Zamówienie nr {D11} z dnia 2026-03-12, kwota 12 345,67 zł, faktura FV/2026/{D4}.",
    "Numer sprawy: {D11}. Sygnatura akt II K {D3}/26. Termin: 14:30.",
    "Kod produktu {D9}, partia {D10}, ilość 1000 szt.",
    "Statystyka: w 2025 r. przyjęto {D3} wniosków, odrzucono {D2}%. Budżet 4 500 000 zł.",
    "Commit a1b2c3d4e5f6, build {D8}, port 8006, timeout 30000 ms.",
    "Spotkanie zespołu w sali 204 o godz. 10:00. Agenda: plan na Q4.",
]
GEN = {
    "PESEL": pesel,
    "NIP": nip,
    "REGON": regon,
    "IBAN": iban,
    "CARD": card,
    "ID_CARD": id_card,
    "PHONE": phone,
    "SECRET": secret,
    "ADDRESS": address,
}


def bad_checksum(n: int) -> str:
    """Digit run of length n that fails the PESEL / NIP / REGON / card checksums."""
    from src.guard.pii import luhn_ok, nip_ok, pesel_ok, regon_ok

    while True:
        s = num(n)
        if not any(f(s) for f in (pesel_ok, nip_ok, regon_ok, luhn_ok)):
            return s


def fill(template: str) -> dict:
    p1, p2 = R.sample(PEOPLE, 2)
    forms = {"nom": 0, "gen": 1, "ins": 2}
    text, spans, i = "", [], 0
    while (a := template.find("{", i)) != -1:
        b = template.index("}", a)
        text += template[i:a]
        key, _, form = template[a + 1 : b].partition(":")
        if key.startswith("D"):
            text += bad_checksum(int(key[1:]))
        else:
            if key.startswith("PERSON"):
                value, kind = (p2 if key == "PERSON2" else p1)[forms[form]], "PERSON"
            elif key == "EMAIL":
                value, kind = email(p1[0]), "EMAIL"
            else:
                value, kind = GEN[key](), key
            spans.append(
                {"kind": kind, "start": len(text), "end": len(text) + len(value)}
            )
            text += value
        i = b + 1
    return {"text": text + template[i:], "spans": spans}


def main() -> None:
    rows = [fill(t) for _ in range(20) for t in TEMPLATES]
    rows += [fill(t) for _ in range(10) for t in NEGATIVES]
    out = Path(__file__).parent / "datasets/pii_pl.jsonl"
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    print(f"{len(rows)} docs -> {out}")


if __name__ == "__main__":
    main()
