"""
app.py
Kerangka Fungsional Antarmuka Streamlit (Barebones Wireframe)
Sistem Pengesahan & Verifikasi E-Sertifikat Digital RSA
"""

from datetime import datetime, timezone, timedelta
import streamlit as st
from rsa_core import generate_keypair
from cert_service import issue_certificate_file, verify_certificate_file

st.set_page_config(page_title="E-Certificate RSA System", layout="wide")

st.title("Sistem Pengesahan E-Sertifikat RSA")

if "rsa_keypair" not in st.session_state:
    st.session_state["rsa_keypair"] = None

tab_issuer, tab_verifier = st.tabs(["Issuer (Penerbitan)", "Verifier (Verifikasi)"])

with tab_issuer:
    st.subheader("1. Pembangkitan Kunci Otoritas")
    p_input = st.number_input("Nilai Bilangan Prima p", min_value=11, value=1009, step=2)
    q_input = st.number_input("Nilai Bilangan Prima q", min_value=11, value=1013, step=2)

    if st.button("Generate Kunci Otoritas"):
        try:
            st.session_state["rsa_keypair"] = generate_keypair(int(p_input), int(q_input))
            st.success("Pasangan kunci otoritas berhasil dibangkitkan.")
        except Exception as err:
            st.error(f"Gagal memproses kunci: {err}")

    current_keys = st.session_state.get("rsa_keypair")
    if current_keys:
        st.text(f"Modulus n: {current_keys['n']}")
        st.text(f"Kunci Publik e: {current_keys['e']}")
        st.text(f"Kunci Privat d (Rahasia Issuer): {current_keys['d']}")
        st.text(f"Totient Phi(n): {current_keys['totient']}")

    st.subheader("2. Penerbitan & Penandatanganan Dokumen")
    doc_file = st.file_uploader("Pilih Berkas Sertifikat Polos", type=["pdf", "png"], key="issue_file")
    default_exp = (datetime.now(timezone.utc) + timedelta(days=365)).date()
    exp_date = st.date_input("Masa Berlaku Dokumen", value=default_exp)

    if st.button("Tandatangani & Terbitkan Sertifikat"):
        if not current_keys:
            st.warning("Bangkitkan pasangan kunci otoritas terlebih dahulu.")
        elif not doc_file:
            st.warning("Pilih berkas sertifikat yang akan disahkan.")
        else:
            try:
                raw_bytes = doc_file.read()
                file_ext = doc_file.name.split(".")[-1].lower()
                base_name = doc_file.name.rsplit(".", 1)[0]
                date_str = exp_date.strftime("%Y-%m-%d")

                # Penandatanganan resmi menggunakan kunci privat d milik otoritas
                signed_bytes, crypto_result = issue_certificate_file(
                    file_bytes=raw_bytes,
                    file_type=file_ext,
                    expiry_date_str=date_str,
                    d=current_keys["d"],
                    n=current_keys["n"]
                )

                st.success("Sertifikat berhasil ditandatangani secara digital.")
                st.download_button(
                    label=f"Unduh Dokumen Bertanda Tangan ({file_ext.upper()})",
                    data=signed_bytes,
                    file_name=f"{base_name}_signed.{file_ext}",
                    mime="application/pdf" if file_ext == "pdf" else "image/png"
                )

                # Data kalkulasi mentah untuk visualisasi edukasi blok RSA
                st.write("Ukuran Chunk Byte:", crypto_result["chunk_size"])
                st.write("Daftar Blok Plaintext (m):", crypto_result["plain_blocks"])
                st.write("Daftar Blok Tanda Tangan Cipher (c):", crypto_result["cipher_blocks"])
                st.text_area("Token Metadata Tanda Tangan:", crypto_result["token"])

            except Exception as err:
                st.error(f"Gagal menandatangani sertifikat: {err}")

with tab_verifier:
    st.subheader("Pemeriksaan Keaslian Dokumen (Publik)")
    verify_file = st.file_uploader("Unggah Berkas yang Akan Diverifikasi", type=["pdf", "png"], key="verify_file")

    default_e = current_keys["e"] if current_keys else 0
    default_n = current_keys["n"] if current_keys else 0

    col_k1, col_k2 = st.columns(2)
    with col_k1:
        e_val = st.number_input("Kunci Publik Verifikasi (e)", min_value=0, value=default_e)
    with col_k2:
        n_val = st.number_input("Modulus Dokumen (n)", min_value=0, value=default_n)

    if st.button("Jalankan Verifikasi"):
        if not verify_file:
            st.warning("Silakan unggah dokumen yang akan diperiksa.")
        elif e_val == 0 or n_val == 0:
            st.warning("Masukkan parameter nilai kunci publik e dan n yang valid.")
        else:
            try:
                v_bytes = verify_file.read()
                v_ext = verify_file.name.split(".")[-1].lower()

                # Verifikasi publik menggunakan kunci publik e
                check_result = verify_certificate_file(
                    file_bytes=v_bytes,
                    file_type=v_ext,
                    e=int(e_val),
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
