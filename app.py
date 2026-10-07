"""
app.py
Kerangka Fungsional Antarmuka Streamlit (Barebones Wireframe) (tolong diperbaiki lagi ya)
Sistem Penerbitan & Verifikasi E-Sertifikat RSA
"""

from datetime import datetime, timezone, timedelta
import streamlit as st
from rsa_core import generate_keypair
from cert_service import issue_certificate_file, verify_certificate_file

st.set_page_config(page_title="E-Certificate RSA System", layout="wide")

st.title("Sistem Pengesahan E-Sertifikat RSA")

# Gunakan rsa_keypair untuk menghindari bentrok dengan method bawaan dict.keys()
if "rsa_keypair" not in st.session_state:
    st.session_state["rsa_keypair"] = None

tab_issuer, tab_verifier = st.tabs(["Issuer (Penerbitan)", "Verifier (Verifikasi)"])

with tab_issuer:
    st.subheader("1. Pembangkitan Kunci Otoritas")
    p_input = st.number_input("Nilai Bilangan Prima p", min_value=11, value=1009, step=2)
    q_input = st.number_input("Nilai Bilangan Prima q", min_value=11, value=1013, step=2)

    if st.button("Generate Kunci"):
        try:
            st.session_state["rsa_keypair"] = generate_keypair(int(p_input), int(q_input))
            st.success("Kunci otoritas berhasil dibangkitkan.")
        except Exception as err:
            st.error(f"Gagal memproses kunci: {err}")

    current_keys = st.session_state.get("rsa_keypair")
    if current_keys:
        st.text(f"Modulus n: {current_keys['n']}")
        st.text(f"Eksponen Publik e: {current_keys['e']}")
        st.text(f"Eksponen Privat d: {current_keys['d']}")
        st.text(f"Totient Phi(n): {current_keys['totient']}")

    st.subheader("2. Penerbitan Dokumen")
    doc_file = st.file_uploader("Pilih Berkas Sertifikat Polos", type=["pdf", "png"], key="issue_file")
    default_exp = (datetime.now(timezone.utc) + timedelta(days=365)).date()
    exp_date = st.date_input("Masa Berlaku Dokumen", value=default_exp)

    if st.button("Terbitkan & Suntikkan Segel RSA"):
        if not current_keys:
            st.warning("Bangkitkan pasangan kunci otoritas terlebih dahulu.")
        elif not doc_file:
            st.warning("Pilih berkas sertifikat yang akan diproses.")
        else:
            try:
                raw_bytes = doc_file.read()
                file_ext = doc_file.name.split(".")[-1].lower()
                date_str = exp_date.strftime("%Y-%m-%d")

                sealed_bytes, crypto_result = issue_certificate_file(
                    file_bytes=raw_bytes,
                    file_type=file_ext,
                    expiry_date_str=date_str,
                    e=current_keys["e"],
                    n=current_keys["n"]
                )

                st.success("Sertifikat berhasil disahkan dan diberi segel kriptografi.")
                st.download_button(
                    label=f"Unduh Dokumen Bersegel ({file_ext.upper()})",
                    data=sealed_bytes,
                    file_name=f"sealed_{doc_file.name}",
                    mime="application/pdf" if file_ext == "pdf" else "image/png"
                )

                # Data kalkulasi mentah siap ditata oleh pengembang frontend
                st.write("Ukuran Chunk Byte:", crypto_result["chunk_size"])
                st.write("Daftar Blok Plaintext (m):", crypto_result["plain_blocks"])
                st.write("Daftar Blok Ciphertext (c):", crypto_result["cipher_blocks"])
                st.text_area("Token Metadata RSA:", crypto_result["token"])

            except Exception as err:
                st.error(f"Gagal menerbitkan sertifikat: {err}")

with tab_verifier:
    st.subheader("Pemeriksaan Keaslian Dokumen")
    verify_file = st.file_uploader("Unggah Berkas yang Akan Diverifikasi", type=["pdf", "png"], key="verify_file")

    default_d = current_keys["d"] if current_keys else 0
    default_n = current_keys["n"] if current_keys else 0

    d_val = st.number_input("Kunci Privat Pengesah (d)", min_value=0, value=default_d)
    n_val = st.number_input("Modulus Dokumen (n)", min_value=0, value=default_n)

    if st.button("Jalankan Verifikasi"):
        if not verify_file:
            st.warning("Silakan unggah dokumen yang akan diperiksa.")
        elif d_val == 0 or n_val == 0:
            st.warning("Masukkan parameter nilai kunci d dan n yang valid.")
        else:
            try:
                v_bytes = verify_file.read()
                v_ext = verify_file.name.split(".")[-1].lower()

                check_result = verify_certificate_file(
                    file_bytes=v_bytes,
                    file_type=v_ext,
                    d=int(d_val),
                    n=int(n_val)
                )

                st.text(f"Status Hasil: {check_result['status']}")
                st.text(f"Pesan Sistem: {check_result['message']}")
                if check_result.get("expiry_date"):
                    st.text(f"Masa Berlaku Terbaca: {check_result['expiry_date']}")
                if check_result.get("visual_hash"):
                    st.text(f"Nilai Hash Dokumen: {check_result['visual_hash']}")

            except Exception as err:
                st.error(f"Terjadi kesalahan saat memproses verifikasi: {err}")
