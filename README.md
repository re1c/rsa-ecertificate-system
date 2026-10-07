# RSA-Based E-Certificate Issuance and Verification System

Implementasi sistem penerbitan dan verifikasi keabsahan dokumen e-sertifikat digital berbasis tanda tangan digital RSA manual murni tanpa dependensi pustaka kriptografi eksternal.

## Kelompok 17 - Kriptografi (A)
* Naswan Nashir Ramadhan (5025231246)
* Alfianz Risqia Ilahi Loven Kary (5025241164)
* Az Zahrra Tasya Adelia (5027241087)

## Arsitektur Tanda Tangan Digital RSA
Sistem mengadopsi mekanisme *single verifiable document* dengan menyematkan token tanda tangan kriptografis ke dalam metadata internal berkas (`.pdf` / `.png`) tanpa mengubah representasi visualnya:

1. **Issuer (Otoritas Penerbit)**:
   - Mengekstrak data visual murni dokumen dan menghitung ringkasan SHA-256 (`visual_hash`).
   - Menggabungkan hash dengan batas waktu kedaluwarsa (`payload = visual_hash + "|" + expiry_date`).
   - Menandatangani payload secara matematis menggunakan **Kunci Privat ($d, n$)**: $c_i = m_i^d \pmod n$.
   - Menyuntikkan string tanda tangan ke metadata internal berkas (`/RSA_Token`) dan menghasilkan output berkas bertanda tangan (`[nama]_signed.[ext]`).

2. **Verifier (Verifikasi Publik)**:
   - Mengekstrak token tanda tangan dari metadata internal berkas.
   - Memulihkan muatan payload secara matematis menggunakan **Kunci Publik Otoritas ($e, n$)**: $m_i = c_i^e \pmod n$.
   - Menghitung ulang nilai hash visual dokumen yang diunggah.
   - Menguji integritas data dan tanggal kedaluwarsa secara terprogram (**VERIFIED**, **TAMPERED**, **EXPIRED**, atau **UNSIGNED**).

## Spesifikasi Modul
* `rsa_core.py`: Modul matematika RSA manual (Extended Euclidean Algorithm, modul exponentiation square-and-multiply, serta penanganan byte chunking Big-Endian).
* `cert_service.py`: Service ekstraksi representasi visual deterministik dan injeksi metadata berkas PDF/PNG.
* `app.py`: Kerangka fungsional antarmuka berbasis Streamlit.
* `tests/`: 20 skenario unit testing otomatis.

## Panduan Menjalankan Sistem

1. Persiapan virtual environment dan dependensi:
```bash
python -m venv .venv
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

## Rencana Pengembangan Lanjutan
* **Frontend UI/UX (`app.py`)**:
  - Penataan antarmuka modern dan kartu status visual (hijau untuk *Verified*, merah untuk *Tampered/Expired*).
  - Penambahan panel edukasi interaktif untuk mensimulasikan tahapan perhitungan modular eksponensiasi per blok ($m_i \rightarrow c_i$) saat presentasi demo kelas.
  - Komponen pratinjau dokumen (*PDF viewer* / *image preview*) sebelum dan sesudah verifikasi.
* **Laporan & Sampel Pengujian**:
  - Penyusunan dokumen laporan teknis dan pembahasan perhitungan matematis RSA.
  - Penyediaan berkas sertifikat tiruan di direktori `samples/` untuk bahan demonstrasi pengujian (skenario valid, manipulasi visual, dan kedaluwarsa).
