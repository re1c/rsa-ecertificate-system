import pytest
from rsa_core import (
    is_prime,
    gcd,
    find_d,
    generate_keypair,
    encrypt_payload,
    decrypt_payload,
)


def test_is_prime_boundaries():
    # test angka negatif, nol, dan satu bukan prima
    assert is_prime(-7) is False
    assert is_prime(0) is False
    assert is_prime(1) is False
    
    # prima terkecil dan prima ganjil
    assert is_prime(2) is True
    assert is_prime(3) is True
    assert is_prime(17) is True
    assert is_prime(101) is True
    assert is_prime(1009) is True
    
    # Komposit genap dan ganjil
    assert is_prime(4) is False
    assert is_prime(9) is False
    assert is_prime(100) is False


def test_gcd():
    assert gcd(48, 18) == 6
    assert gcd(17, 31) == 1
    assert gcd(100, 25) == 25
    assert gcd(0, 5) == 5


def test_find_d():
    # Contoh kasus: e = 7, totient_n = 120 -> 7 * d mod 120 == 1
    d, k = find_d(7, 120)
    assert (7 * d) % 120 == 1
    assert k == (7 * d - 1) // 120


def test_generate_keypair():
    keys = generate_keypair(61, 53)
    assert keys["n"] == 3233
    assert keys["totient"] == 3120
    assert (keys["e"] * keys["d"]) % keys["totient"] == 1
    assert keys["k"] == (keys["e"] * keys["d"] - 1) // keys["totient"]


def test_generate_keypair_validations():
    # Menolak input non-prima
    with pytest.raises(ValueError):
        generate_keypair(10, 20)

    # Menolak prima identik (p == q)
    with pytest.raises(ValueError):
        generate_keypair(17, 17)

    # Menolak modulus n terlalu kecil untuk encoding byte
    with pytest.raises(ValueError):
        generate_keypair(3, 5)

    # Menolak preferred_e di luar batas 1 < e < totient(n)
    with pytest.raises(ValueError):
        generate_keypair(61, 53, preferred_e=1)

    with pytest.raises(ValueError):
        generate_keypair(61, 53, preferred_e=4000)

    # Menolak preferred_e yang tidak relatif prima terhadap totient(n)
    with pytest.raises(ValueError):
        generate_keypair(61, 53, preferred_e=6)


def test_payload_roundtrip_integrity():
    keys = generate_keypair(1009, 1013)
    payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|2027-10-09"

    enc = encrypt_payload(payload, keys["e"], keys["n"])
    dec = decrypt_payload(enc["token"], keys["d"], keys["n"])

    assert dec["is_corrupted"] is False
    assert dec["recovered_text"] == payload


def test_payload_unicode_and_symbols():
    keys = generate_keypair(1009, 1013)
    payload = "Peserta: Budi Santoso | Predikat: Cum Laude ⭐ | Tanggal: 2026-10-09"

    enc = encrypt_payload(payload, keys["e"], keys["n"])
    dec = decrypt_payload(enc["token"], keys["d"], keys["n"])

    assert dec["is_corrupted"] is False
    assert dec["recovered_text"] == payload


def test_tampered_token_handling():
    keys = generate_keypair(1009, 1013)
    payload = "payload_otentik|2027-10-09"
    enc = encrypt_payload(payload, keys["e"], keys["n"])

    tampered_token = enc["token"][:-4] + "9999"
    dec = decrypt_payload(tampered_token, keys["d"], keys["n"])

    assert dec["is_corrupted"] is True
    assert dec["recovered_text"] is None


def test_malformed_token_format():
    keys = generate_keypair(1009, 1013)
    dec = decrypt_payload("token_rusak_tanpa_delimiter", keys["d"], keys["n"])
    assert dec["is_corrupted"] is True
    assert dec["recovered_text"] is None
