"""
rsa_core.py
Modul Kriptografi Kunci Publik RSA Manual (Murni Tanpa Library Kriptografi Eksternal)
"""

def is_prime(num: int) -> bool:
    """Uji bilangan prima manual menggunakan metode Trial Division."""
    if num < 2:
        return False
    if num in (2, 3):
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True


def gcd(a: int, b: int) -> int:
    """Kalkulasi Greatest Common Divisor menggunakan Algoritma Euclidean."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Algoritma Extended Euclidean.
    Menghasilkan (gcd, x, y) sedemikian rupa sehingga a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def find_d(e: int, totient_n: int) -> tuple[int, int]:
    """
    Pencarian kunci privat d secara iteratif berbasis rumus modul perkuliahan:
    d = (1 + k * totient_n) / e untuk k = 1, 2, 3, ... hingga menghasilkan bilangan bulat.
    Mengembalikan pasangan (d, k) untuk pembuktian relasi e*d = 1 + k*totient_n.
    """
    k = 1
    # Loop iteratif rumus slide perkuliahan
    while k < e + 100000:
        pembilang = 1 + (k * totient_n)
        if pembilang % e == 0:
            return pembilang // e, k
        k += 1

    # Fallback Extended Euclidean Algorithm jika nilai e sangat besar
    g, x, _ = extended_gcd(e, totient_n)
    if g != 1:
        raise ValueError("Invers modular tidak ditemukan karena e dan totient(n) tidak relatif prima.")

    d = x % totient_n
    if d < 0:
        d += totient_n

    k_val = (e * d - 1) // totient_n
    return d, k_val


def mod_pow(base: int, exp: int, mod: int) -> int:
    """
    Perpangkatan modular manual menggunakan algoritma Square-and-Multiply.
    Menghitung (base^exp) % mod tanpa risiko memory overflow.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


def generate_keypair(p: int, q: int, preferred_e: int = None) -> dict:
    """
    Pembangkitan pasangan kunci RSA lengkap (p, q, n, totient, e, d, k).
    """
    if not is_prime(p) or not is_prime(q):
        raise ValueError("Parameter p dan q harus berupa bilangan prima.")
    if p == q:
        raise ValueError("Nilai p dan q tidak boleh sama.")

    n = p * q
    if n < 256:
        raise ValueError("Modulus n terlalu kecil untuk encoding byte minimal (n >= 256).")

    totient_n = (p - 1) * (q - 1)

    if preferred_e is not None:
        if not (1 < preferred_e < totient_n):
            raise ValueError(f"Nilai e harus berada pada rentang 1 < e < {totient_n}.")
        if gcd(preferred_e, totient_n) != 1:
            raise ValueError(f"Nilai e={preferred_e} tidak relatif prima terhadap totient(n)={totient_n}.")
        e = preferred_e
    else:
        # Default pencarian e ganjil terkecil yang relatif prima
        candidate = 65537 if totient_n > 65537 and gcd(65537, totient_n) == 1 else 3
        while candidate < totient_n:
            if gcd(candidate, totient_n) == 1:
                break
            candidate += 2
        else:
            raise ValueError("Tidak ditemukan nilai e yang coprime terhadap totient(n).")
        e = candidate

    d, k_val = find_d(e, totient_n)

    return {
        "p": p,
        "q": q,
        "n": n,
        "totient": totient_n,
        "e": e,
        "d": d,
        "k": k_val,
    }


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    """Standardisasi panjang data byte menggunakan padding PKCS#7 manual."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    """Pembersihan padding PKCS#7 manual dengan verifikasi integritas format."""
    if not data:
        raise ValueError("Data byte kosong.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Padding PKCS#7 tidak valid.")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 korup.")
    return data[:-pad_len]


def get_chunk_byte_size(n: int) -> int:
    """Menghitung kapasitas byte maksimum per blok agar nilai integer m < n."""
    bit_len = n.bit_length()
    byte_size = (bit_len - 1) // 8
    return max(1, byte_size)


def encrypt_payload(payload_str: str, e: int, n: int) -> dict:
    """
    Enkripsi string payload menjadi token segel RSA per blok numerik.
    """
    raw_bytes = payload_str.encode("utf-8")
    chunk_size = get_chunk_byte_size(n)
    padded_bytes = pkcs7_pad(raw_bytes, chunk_size)

    plain_blocks = []
    cipher_blocks = []

    for i in range(0, len(padded_bytes), chunk_size):
        chunk = padded_bytes[i:i + chunk_size]
        m_int = int.from_bytes(chunk, byteorder="big")
        c_int = mod_pow(m_int, e, n)
        plain_blocks.append(m_int)
        cipher_blocks.append(c_int)

    # Format token: <chunk_size>:<c1> <c2> <c3>...
    token = f"{chunk_size}:" + " ".join(str(c) for c in cipher_blocks)

    return {
        "token": token,
        "plain_blocks": plain_blocks,
        "cipher_blocks": cipher_blocks,
        "chunk_size": chunk_size,
    }


def decrypt_payload(token_str: str, d: int, n: int) -> dict:
    """
    Dekripsi token cipher kembali ke teks payload asli dengan penanganan anomali format.
    """
    try:
        parts = token_str.strip().split(":")
        if len(parts) != 2:
            return {"recovered_text": None, "decrypted_blocks": [], "is_corrupted": True}

        chunk_size = int(parts[0])
        cipher_blocks = [int(c) for c in parts[1].split() if c]

        reconstructed_bytes = bytearray()
        decrypted_blocks = []

        for c_int in cipher_blocks:
            m_int = mod_pow(c_int, d, n)
            decrypted_blocks.append(m_int)
            chunk_bytes = m_int.to_bytes(chunk_size, byteorder="big")
            reconstructed_bytes.extend(chunk_bytes)

        unpadded_bytes = pkcs7_unpad(bytes(reconstructed_bytes))
        recovered_text = unpadded_bytes.decode("utf-8")

        return {
            "recovered_text": recovered_text,
            "decrypted_blocks": decrypted_blocks,
            "is_corrupted": False,
        }
    except Exception:
        return {
            "recovered_text": None,
            "decrypted_blocks": [],
            "is_corrupted": True,
        }
