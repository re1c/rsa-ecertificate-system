# RSA-Based E-Certificate Issuance and Verification System

Implementasi sistem penerbitan dan verifikasi keabsahan dokumen e-sertifikat digital berbasis kriptografi kunci publik RSA manual tanpa pustaka kriptografi pihak ketiga.

## Kelompok 17 - Kriptografi (A)
* Naswan Nashir Ramadhan (5025231246)
* Alfianz Risqia Ilahi Loven Kary (5025241164)
* Az Zahrra Tasya Adelia (5027241087)

## Struktur Modul Sistem
* `rsa_core.py`: Modul kalkulasi matematika RSA manual (Extended Euclidean Algorithm, eksponensiasi modular square-and-multiply, dan penanganan blok byte).
* `cert_service.py`: Service pengekstraksi representasi visual dokumen PDF/PNG dan injeksi segel token metadata.
* `app.py`: Kerangka antarmuka pengguna berbasis Streamlit.
* `tests/`: Kumpulan 20 skenario unit testing otomatis.

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

## Pembagian Peran Lanjutan
* **Frontend UI (`app.py`)**: Pengembangan estetika antarmuka, penataan tata letak kartu status, perapian tabel visualisasi blok RSA, dan pratinjau dokumen.
* **Laporan & Sampel Berkas**: Penyusunan laporan resmi pengujian matematis serta penyiapan sampel dokumen sertifikat di folder `samples/` untuk bahan demonstrasi.
