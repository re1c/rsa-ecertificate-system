# RSA-Based E-Certificate Issuance and Verification System

Implementasi sistem penerbitan dan verifikasi keaslian e-sertifikat digital berbasis algoritma kunci publik RSA manual (tanpa pustaka kriptografi eksternal).

## Kelompok 17 - Kriptografi (A)
* Naswan Nashir Ramadhan (5025231246)
* Alfianz Risqia Ilahi Loven Kary (5025241164)
* Az Zahrra Tasya Adelia (5027241087)

## Arsitektur Sistem
Sistem menggunakan pendekatan *single verifiable document* dengan menyematkan token kriptografi ke dalam metadata internal berkas (`.pdf` / `.png`) tanpa mengubah representasi visualnya.

1. **Issuer**:
   - Menghitung ringkasan SHA-256 dari konten visual berkas final.
   - Menggabungkan hash visual dengan batas waktu kedaluwarsa (`payload = hash + "|" + expired`).
   - Mengenkripsi payload secara manual menggunakan kunci RSA menjadi `rsa_token`.
   - Menyuntikkan `rsa_token` ke metadata internal dokumen (`Document Info` pada PDF / `tEXt chunk` pada PNG).
2. **Verifier**:
   - Mengekstrak `rsa_token` dari metadata berkas yang diunggah.
   - Mendekripsi `rsa_token` secara manual untuk memulihkan hash asli dan batas kedaluwarsa.
   - Menghitung ulang hash visual dari berkas yang diunggah.
   - Memvalidasi integritas visual dan tanggal kedaluwarsa secara terprogram (status: **VERIFIED**, **TAMPERED**, **EXPIRED**, atau **UNSIGNED**).

## Spesifikasi API Modul Inti (`rsa_core.py`)
Modul ini siap diintegrasikan langsung ke antarmuka aplikasi (`app.py`):

* `generate_keypair(p: int, q: int, preferred_e: int = None) -> dict`
  - Mengembalikan parameter: `{"p", "q", "n", "totient", "e", "d", "k"}`
* `encrypt_payload(payload_str: str, e: int, n: int) -> dict`
  - Mengembalikan struktur: `{"token", "plain_blocks", "cipher_blocks", "chunk_size"}`
* `decrypt_payload(token_str: str, d: int, n: int) -> dict`
  - Mengembalikan hasil: `{"recovered_text", "decrypted_blocks", "is_corrupted"}`

## Eksekusi Pengujian Lokal
```bash
pytest -v
```
