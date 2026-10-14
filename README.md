# RSA-Based E-Certificate Issuance and Verification System

Implementasi sistem penerbitan dan verifikasi keabsahan dokumen e-sertifikat digital berbasis tanda tangan digital RSA manual, tanpa dependensi pustaka kriptografi pihak ketiga.

## Kelompok 17 - Kriptografi (A)
* Naswan Nashir Ramadhan (5025231246)
* Alfianz Risqia Ilahi Loven Kary (5025241164)
* Az Zahrra Tasya Adelia (5027241087)

## Arsitektur Tanda Tangan Digital RSA
Sistem mengadopsi mekanisme single verifiable document dengan menyematkan token tanda tangan kriptografis langsung ke dalam metadata internal berkas (.pdf atau .png) tanpa mengubah representasi visualnya:

1. **Penerbitan (Issuer)**:
   - Mengekstrak representasi visual dokumen secara deterministik (rendering halaman PDF ke RGB pixmap via PyMuPDF atau ekstraksi biner RGBA pada PNG).
   - Menghitung ringkasan SHA-256 dari representasi visual (visual_hash).
   - Menyusun string muatan: payload = visual_hash + "|" + expiry_date.
   - Mengonversi payload ke representasi byte, menambahkan padding PKCS#7 manual, memecahnya ke dalam blok integer m_i < n, lalu menandatanganinya menggunakan Kunci Privat Otoritas (d, n):
     $$c_i = m_i^d \pmod n$$
   - Menggabungkan deretan blok ciphertext c_i menjadi token string dan menyuntikkannya ke metadata dokumen (/RSA_Token).

2. **Verifikasi Publik (Verifier)**:
   - Mengekstrak token /RSA_Token dari metadata internal berkas.
   - Memulihkan muatan payload secara matematis menggunakan Kunci Publik Otoritas (e, n):
     $$m_i = c_i^e \pmod n$$
   - Menghitung ulang hash visual dari berkas yang diunggah.
   - Menguji keabsahan dokumen berdasarkan 4 klasifikasi status:
     - **VERIFIED**: Tanda tangan sah secara matematis, hash visual cocok, dan masa berlaku dokumen aktif.
     - **TAMPERED**: Konten visual dimanipulasi, nilai token rusak, atau kunci publik verifikator tidak cocok.
     - **EXPIRED**: Tanda tangan sah, namun batas waktu kedaluwarsa dokumen telah terlewati.
     - **UNSIGNED**: Berkas tidak memiliki metadata segel resmi.

## Struktur Berkas dan Artefak Proyek
* `rsa_core.py`: Modul logika matematika RSA murni (uji prima Trial Division 6k ± 1, generator prima acak, PBB Euclidean, Extended Euclidean Algorithm, eksponensiasi modular Square-and-Multiply, byte chunking, dan padding PKCS#7).
* `cert_service.py`: Service penanganan representasi visual dokumen dan injeksi metadata berkas PDF/PNG.
* `app.py`: Antarmuka web interaktif berbasis Streamlit lengkap dengan simulator perhitungan per blok dan laboratorium kalkulasi modular.
* `cek_metadata.py`: Skrip utilitas CLI sederhana untuk memeriksa keberadaan dan isi token metadata pada berkas PDF.
* `Laporan/`: Dokumen laporan teknis resmi kelompok dalam format .docx dan .pdf.
* `tests/`: Kumpulan 21 skenario unit test otomatis untuk pengujian logika RSA dan integritas dokumen.

## Panduan Menjalankan Sistem

1. Persiapan virtual environment dan dependensi:
```bash
python -m venv .venv
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Menjalankan pengujian otomatis:
```bash
pytest -v
```

3. Menjalankan aplikasi web:
```bash
streamlit run app.py
```

4. Menjalankan skrip cek metadata (opsional):
```bash
python cek_metadata.py
```