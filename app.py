"""
app.py
Antarmuka Streamlit - Sistem Pengesahan & Verifikasi E-Sertifikat Digital RSA

Fitur UI:
  - Kartu status berwarna (VERIFIED / TAMPERED / EXPIRED / UNSIGNED) + daftar pemeriksaan.
  - Panel edukasi: tahapan pembangkitan kunci dan perhitungan modular eksponensiasi per blok
    (m_i -> c_i saat penerbitan, c_i -> m_i saat verifikasi).
  - Pratinjau dokumen (PNG / PDF) sebelum & sesudah penandatanganan / verifikasi.
  - Pembangkit bilangan prima acak pada UI memanfaatkan pengujian rsa_core.is_prime().
  - Hasil disimpan di st.session_state sehingga tidak hilang saat tombol unduh ditekan.

Backend (rsa_core.py, cert_service.py) murni tanpa library kriptografi.
"""

import html
import io
import random
from datetime import datetime, timedelta, timezone

import streamlit as st
from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader

import rsa_core
from cert_service import (
    compute_sha256,
    extract_visual_bytes,
    issue_certificate_file,
    verify_certificate_file,
)
from rsa_core import generate_keypair

st.set_page_config(page_title="E-Certificate RSA System", page_icon="🔐", layout="wide")

MAX_PRIME_INPUT = 10**13   # batas aman uji prima trial division (backend)
STATUS_STYLE = {
    "VERIFIED": ("s-verified", "✔", "Dokumen sah"),
    "TAMPERED": ("s-tampered", "✖", "Dokumen dimanipulasi / segel tidak valid"),
    "EXPIRED": ("s-expired", "⏱", "Dokumen otentik, tetapi masa berlaku habis"),
    "UNSIGNED": ("s-unsigned", "○", "Dokumen tidak memiliki segel"),
}

# ----------------------------------------------------------------------------
# CSS
# ----------------------------------------------------------------------------
CSS = """
<style>
.block-container{padding-top:2.2rem;max-width:1200px}
.hero h1{margin:0 0 .15rem 0;font-size:2rem}
.hero p{margin:0;opacity:.75}
.stepper{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0 .6rem}
.step-pill{display:flex;align-items:center;gap:.5rem;padding:.35rem .85rem;border-radius:999px;
  border:1px solid rgba(128,128,128,.4);font-size:.9rem}
.step-pill .dot{width:1.45rem;height:1.45rem;border-radius:50%;display:grid;place-items:center;
  font-size:.75rem;font-weight:700;background:rgba(128,128,128,.28)}
.step-pill.done{border-color:#16a34a}
.step-pill.done .dot{background:#16a34a;color:#fff}
.status-card{display:flex;gap:1rem;align-items:center;padding:1.05rem 1.3rem;border-radius:14px;
  border:1.5px solid;margin:.4rem 0 1rem}
.status-card .s-icon{font-size:2.3rem;line-height:1;font-weight:700}
.status-card .s-title{font-size:1.45rem;font-weight:800;letter-spacing:.03em}
.status-card .s-msg{opacity:.9}
.s-verified{background:rgba(22,163,74,.13);border-color:#16a34a}.s-verified .s-icon,.s-verified .s-title{color:#16a34a}
.s-tampered{background:rgba(220,38,38,.12);border-color:#dc2626}.s-tampered .s-icon,.s-tampered .s-title{color:#dc2626}
.s-expired{background:rgba(217,119,6,.14);border-color:#d97706}.s-expired .s-icon,.s-expired .s-title{color:#d97706}
.s-unsigned{background:rgba(100,116,139,.15);border-color:#64748b}.s-unsigned .s-icon,.s-unsigned .s-title{color:#64748b}
.badge{display:inline-block;padding:.1rem .6rem;border-radius:999px;font-size:.72rem;font-weight:700;
  margin-left:.45rem;vertical-align:middle;color:#fff}
.badge-secret{background:#b45309}.badge-public{background:#1d4ed8}
.chk{display:flex;gap:.7rem;padding:.3rem 0;align-items:flex-start}
.chk .ic{font-weight:800;width:1.3rem;text-align:center}
.chk.ok .ic{color:#16a34a}.chk.fail .ic{color:#dc2626}.chk.warn .ic{color:#d97706}.chk.skip{opacity:.45}
.stepno{display:inline-block;min-width:1.7rem;text-align:center;border-radius:999px;background:#1d4ed8;color:#fff;
  font-weight:700;margin-right:.5rem;padding:.05rem .4rem}
.formula-note{opacity:.8;font-size:.9rem}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

# ----------------------------------------------------------------------------
# State
# ----------------------------------------------------------------------------
for _k, _v in {
    "rsa_keypair": None, "issue_result": None, "verify_result": None,
    "keygen_error": None, "verify_error": None, "demo_cert": None,
    "kp_p": 1009, "kp_q": 1013, "kp_e": "",
}.items():
    st.session_state.setdefault(_k, _v)

keys = st.session_state["rsa_keypair"]


# ----------------------------------------------------------------------------
# Helper murni (tidak mengubah logika kriptografi backend)
# ----------------------------------------------------------------------------
def parse_int(text: str, label: str) -> int:
    cleaned = str(text).strip().replace(" ", "").replace(",", "").replace("_", "")
    if not cleaned.isdigit():
        raise ValueError(f"{label} harus berupa bilangan bulat positif.")
    return int(cleaned)


def short(num, keep=14) -> str:
    s = str(num)
    return s if len(s) <= keep * 2 + 3 else f"{s[:keep]}…{s[-keep:]} ({len(s)} digit)"


def fingerprint(e: int, n: int) -> str:
    h = compute_sha256(f"{e}:{n}".encode()).upper()[:16]
    return " ".join(h[i:i + 4] for i in range(0, 16, 4))


def badge(kind: str) -> str:
    return '<span class="badge badge-secret">rahasia</span>' if kind == "secret" else '<span class="badge badge-public">publik</span>'


def euclid_chain(a: int, b: int):
    rows = []
    while b:
        rows.append((a, b, a // b, a % b))
        a, b = b, a % b
    return a, rows


def modpow_trace(base: int, exp: int, mod: int):
    """Jejak square-and-multiply (urutan sama dengan rsa_core.mod_pow: bit terendah dulu)."""
    result, b, e, i, rows = 1, base % mod, exp, 0, []
    while e > 0:
        bit = e & 1
        if bit:
            result = (result * b) % mod
        rows.append({"i": i, "bit eksponen": bit, "basis^(2^i) mod n": str(b), "hasil sementara": str(result)})
        b = (b * b) % mod
        e >>= 1
        i += 1
    return result, rows


def render_modpow(base: int, exp: int, mod: int, sym_base: str, sym_exp: str, sym_out: str):
    """Tampilkan satu perhitungan modular eksponensiasi secara edukatif."""
    result, rows = modpow_trace(base, exp, mod)
    assert result == rsa_core.mod_pow(base, exp, mod)
    st.markdown(f"**{sym_out} = {sym_base}^{sym_exp} mod n**")
    st.code(f"{sym_out} = {short(base)} ^ {short(exp)} mod {short(mod)}\n{sym_out} = {result}", language="text")
    st.caption(f"Eksponen {sym_exp} dalam biner ({exp.bit_length()} bit): " +
               (bin(exp)[2:] if exp.bit_length() <= 64 else bin(exp)[2:34] + "…"))
    if len(rows) > 24:
        st.caption(f"Eksponen panjang: menampilkan 12 langkah pertama dan 6 terakhir dari {len(rows)} langkah.")
        rows = rows[:12] + rows[-6:]
    st.dataframe(rows, hide_index=True, width="stretch")
    return result


def chunk_text(m_int: int, chunk_size: int) -> str:
    raw = m_int.to_bytes(chunk_size, "big") if m_int < 256 ** chunk_size else b""
    return "".join(chr(b) if 32 <= b < 127 else "·" for b in raw)


def read_token(file_bytes: bytes, ext: str):
    try:
        if ext == "pdf":
            md = PdfReader(io.BytesIO(file_bytes)).metadata
            return str(md["/RSA_Token"]) if md and "/RSA_Token" in md else None
        if ext == "png":
            with Image.open(io.BytesIO(file_bytes)) as img:
                return img.text.get("RSA_Token")
    except Exception:
        return None
    return None


def parse_token(token: str):
    try:
        size, rest = token.strip().split(":")
        return int(size), [int(c) for c in rest.split() if c]
    except Exception:
        return None, []


def make_sample_certificate(name: str, title: str) -> bytes:
    """Sertifikat PNG polos untuk demo (tanpa perlu menyiapkan berkas)."""
    w, h = 1200, 850
    img = Image.new("RGB", (w, h), (252, 250, 243))
    d = ImageDraw.Draw(img)
    d.rectangle((24, 24, w - 24, h - 24), outline=(30, 58, 138), width=8)
    d.rectangle((44, 44, w - 44, h - 44), outline=(180, 140, 40), width=3)

    def font(size):
        try:
            return ImageFont.load_default(size=size)
        except Exception:
            return ImageFont.load_default()

    def centered(text, y, size, fill):
        f = font(size)
        box = d.textbbox((0, 0), text, font=f)
        d.text(((w - (box[2] - box[0])) / 2, y), text, font=f, fill=fill)

    centered("SERTIFIKAT", 150, 84, (30, 58, 138))
    centered(title or "Penghargaan", 270, 40, (60, 60, 60))
    centered("diberikan kepada", 380, 32, (90, 90, 90))
    centered(name or "Nama Penerima", 440, 68, (20, 20, 20))
    centered("atas partisipasi dan kontribusinya", 570, 32, (90, 90, 90))
    centered("Kelompok 17 - Kriptografi", 710, 28, (120, 120, 120))
    out = io.BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


def preview(file_bytes: bytes, ext: str, caption: str = "", key: str = "pv"):
    if ext == "png":
        st.image(file_bytes, caption=caption or None)
        return
    try:
        st.pdf(io.BytesIO(file_bytes), height=420, key=key)
        if caption:
            st.caption(caption)
    except Exception as err:
        try:
            pages = len(PdfReader(io.BytesIO(file_bytes)).pages)
        except Exception:
            pages = "?"
        st.info(f"Pratinjau PDF tidak tersedia ({pages} halaman): {type(err).__name__}")


def status_card(status: str, message: str):
    cls, icon, _ = STATUS_STYLE.get(status, STATUS_STYLE["UNSIGNED"])
    st.markdown(
        f'<div class="status-card {cls}"><div class="s-icon">{icon}</div>'
        f'<div><div class="s-title">{html.escape(status)}</div><div class="s-msg">{html.escape(message)}</div></div></div>',
        unsafe_allow_html=True)


def build_checklist(res: dict):
    s, msg = res["status"], res.get("message", "").lower()
    if s == "VERIFIED":
        states = ["ok", "ok", "ok", "ok"]
    elif s == "EXPIRED":
        states = ["ok", "ok", "ok", "warn"]
    elif s == "UNSIGNED":
        states = ["fail", "skip", "skip", "skip"]
    elif "current_hash" in res:
        states = ["ok", "ok", "fail", "skip"]
    elif "tanggal" in msg:
        states = ["ok", "ok", "ok", "fail"]
    else:
        states = ["ok", "fail", "skip", "skip"]
    labels = [
        "Segel RSA (/RSA_Token) ditemukan di metadata",
        "Tanda tangan dapat dipulihkan dengan kunci publik & format payload valid",
        "Hash visual dokumen yang dihitung ulang sama dengan hash di dalam segel",
        "Masa berlaku belum lewat",
    ]
    icons = {"ok": "✔", "fail": "✖", "warn": "⚠", "skip": "–"}
    rows = "".join(f'<div class="chk {st_}"><div class="ic">{icons[st_]}</div><div>{lbl}</div></div>'
                   for st_, lbl in zip(states, labels))
    st.markdown(rows, unsafe_allow_html=True)


def reset_session():
    for k in ("rsa_keypair", "issue_result", "verify_result", "keygen_error", "verify_error", "demo_cert"):
        st.session_state[k] = None


def apply_preset(p: int, q: int, e: str):
    st.session_state["kp_p"], st.session_state["kp_q"], st.session_state["kp_e"] = p, q, e


def apply_random_primes():
    """Mencari pasangan bilangan prima p dan q acak valid memanfaatkan uji rsa_core.is_prime()."""
    while True:
        p = random.randrange(1001, 5000, 2)
        if rsa_core.is_prime(p):
            break
    while True:
        q = random.randrange(1001, 5000, 2)
        if q != p and rsa_core.is_prime(q):
            break
    st.session_state["kp_p"], st.session_state["kp_q"], st.session_state["kp_e"] = p, q, ""


# ----------------------------------------------------------------------------
# Sidebar
# ----------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🔐 RSA E-Certificate")
    st.caption("Kelompok 17 - Kriptografi (A)")
    if keys:
        st.success("Kunci otoritas aktif")
        st.markdown("Sidik jari kunci publik")
        st.code(fingerprint(keys["e"], keys["n"]), language="text")
        st.caption(f"n = {keys['n'].bit_length()} bit")
    else:
        st.info("Belum ada kunci. Mulai dari tab **Kunci Otoritas**.")
    if st.button("Reset sesi", width="stretch"):
        reset_session()
        st.rerun()
    with st.expander("Catatan mode demo"):
        st.markdown(
            "- Ukuran kunci kecil dipakai agar perhitungan bisa dilacak manual. **Kunci sekecil ini tidak aman** "
            "dan hanya untuk pembelajaran.\n"
            "- Kunci privat sengaja ditampilkan untuk tujuan edukasi.\n"
            "- Dokumen dianggap sah hanya jika diverifikasi dengan **kunci publik penerbit yang sama**."
        )

# ----------------------------------------------------------------------------
# Header + stepper
# ----------------------------------------------------------------------------
st.markdown('<div class="hero"><h1>Sistem Pengesahan E-Sertifikat RSA</h1>'
            '<p>Tanda tangan digital RSA manual: kunci privat menandatangani, kunci publik memverifikasi.</p></div>',
            unsafe_allow_html=True)
stepper_slot = st.empty()   # diisi di akhir skrip agar langkah selalu mutakhir

tab_keys, tab_issue, tab_verify, tab_learn = st.tabs(
    ["🔑 Kunci Otoritas", "✍️ Penerbitan", "🔍 Verifikasi", "📘 Alur & Lab Rumus"])

# ============================================================================
# TAB 1 - KUNCI
# ============================================================================
with tab_keys:
    st.subheader("Pembangkitan Kunci Otoritas")
    col_in, col_out = st.columns([1, 1.6], gap="large")

    with col_in:
        st.caption("Gunakan nilai acak, masukkan sendiri, atau pilih contoh materi.")
        b1, b2, b3 = st.columns(3)
        b1.button("Contoh materi", on_click=apply_preset, args=(47, 71, "79"), width="stretch", help="p=47, q=71, e=79 (contoh Alice di slide)")
        b2.button("Bawaan", on_click=apply_preset, args=(1009, 1013, ""), width="stretch", help="Kembali ke nilai awal p=1009, q=1013")
        b3.button("Acak baru", on_click=apply_random_primes, width="stretch", help="Pilih dua bilangan prima p dan q baru secara acak")
        st.number_input("Bilangan prima p", min_value=11, step=1, key="kp_p")
        st.number_input("Bilangan prima q", min_value=11, step=1, key="kp_q")
        st.text_input(
            "Eksponen publik e (opsional, kosong = otomatis)",
            placeholder="65537",
            key="kp_e",
            help="Kosongkan untuk otomatis menggunakan eksponen standar 65537 (atau nilai relatif prima terkecil)."
        )
        if st.button("Bangkitkan kunci otoritas", type="primary", width="stretch"):
            try:
                p, q = int(st.session_state["kp_p"]), int(st.session_state["kp_q"])
                if max(p, q) > MAX_PRIME_INPUT:
                    raise ValueError(f"p dan q maksimal {MAX_PRIME_INPUT:,} (uji prima trial division).".replace(",", "."))
                e_txt = st.session_state["kp_e"].strip()
                e_val = parse_int(e_txt, "e") if e_txt else None
                st.session_state["rsa_keypair"] = generate_keypair(p, q, e_val)
                st.session_state["verify_result"] = None
                st.session_state["keygen_error"] = None
            except Exception as err:
                st.session_state["keygen_error"] = str(err)
            st.rerun()
        if st.session_state["keygen_error"]:
            st.error(st.session_state["keygen_error"])

    with col_out:
        if not keys:
            st.info("Belum ada kunci. Isi p dan q di sebelah kiri lalu tekan **Bangkitkan kunci otoritas**.")
        else:
            k = keys
            with st.container(border=True):
                st.markdown(f'<span class="stepno">1</span>**Pilih dua bilangan prima p ≠ q** {badge("secret")}', unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                c1.code(f"p = {k['p']}", language="text")
                c2.code(f"q = {k['q']}", language="text")
            with st.container(border=True):
                st.markdown(f'<span class="stepno">2</span>**Modulus** n = p × q {badge("public")}', unsafe_allow_html=True)
                st.code(f"n = {k['n']}   ({k['n'].bit_length()} bit)", language="text")
            with st.container(border=True):
                st.markdown(f'<span class="stepno">3</span>**Totient Euler** Φ(n) = (p − 1)(q − 1) {badge("secret")}', unsafe_allow_html=True)
                st.code(f"Φ(n) = {k['p'] - 1} × {k['q'] - 1} = {k['totient']}", language="text")
            with st.container(border=True):
                st.markdown(f'<span class="stepno">4</span>**Eksponen publik** e, syarat PBB(e, Φ(n)) = 1 {badge("public")}', unsafe_allow_html=True)
                g, chain = euclid_chain(k["totient"], k["e"])
                st.code(f"e = {k['e']}\n" + "\n".join(f"{a} = {q_}×{b} + {r}" for a, b, q_, r in chain[:12]) +
                        ("\n…" if len(chain) > 12 else "") + f"\nPBB = {g}  ✔ relatif prima", language="text")
            with st.container(border=True):
                st.markdown(f'<span class="stepno">5</span>**Eksponen privat** d dari e·d = 1 + k·Φ(n) {badge("secret")}', unsafe_allow_html=True)
                st.code(f"k = {k['k']}\nd = (1 + {k['k']} × {k['totient']}) / {k['e']} = {k['d']}\n"
                        f"cek: e·d mod Φ(n) = {(k['e'] * k['d']) % k['totient']}", language="text")
                if k["k"] <= 150:
                    with st.expander("Lihat percobaan nilai k (seperti di materi)"):
                        trial = []
                        for kk in range(1, k["k"] + 1):
                            num = 1 + kk * k["totient"]
                            trial.append({"k": kk, "1 + k·Φ(n)": str(num), "mod e": num % k["e"],
                                          "habis dibagi e?": "✔ d = " + str(num // k["e"]) if num % k["e"] == 0 else "—"})
                        st.dataframe(trial, hide_index=True, width="stretch")
                else:
                    st.caption("Nilai k besar, tabel percobaan tidak ditampilkan.")
            with st.container(border=True):
                st.markdown('<span class="stepno">6</span>**Pasangan kunci terbentuk**', unsafe_allow_html=True)
                kc1, kc2 = st.columns(2)
                kc1.markdown(f"Kunci publik (e, n) {badge('public')}", unsafe_allow_html=True)
                kc1.code(f"e = {k['e']}\nn = {k['n']}", language="text")
                kc2.markdown(f"Kunci privat (d, n) {badge('secret')}", unsafe_allow_html=True)
                kc2.code(f"d = {k['d']}\nn = {k['n']}", language="text")
                st.caption(f"Sidik jari kunci publik: {fingerprint(k['e'], k['n'])}")

# ============================================================================
# TAB 2 - PENERBITAN
# ============================================================================
with tab_issue:
    st.subheader("Penerbitan & Penandatanganan Dokumen")
    if not keys:
        st.info("Bangkitkan kunci otoritas dulu di tab **Kunci Otoritas**.")
    else:
        left, right = st.columns([1, 1.2], gap="large")
        with left:
            source = st.radio("Sumber berkas", ["Unggah berkas", "Buat sertifikat contoh"], horizontal=True)
            doc_bytes, doc_name, doc_ext = None, None, None
            if source == "Unggah berkas":
                up = st.file_uploader("Berkas sertifikat polos (PDF / PNG)", type=["pdf", "png"], key="issue_file")
                if up:
                    doc_bytes, doc_name, doc_ext = up.getvalue(), up.name.rsplit(".", 1)[0], up.name.rsplit(".", 1)[-1].lower()
            else:
                nm = st.text_input("Nama penerima", "Budi Santoso")
                ttl = st.text_input("Judul", "Penghargaan Peserta Terbaik")
                st.session_state["demo_cert"] = make_sample_certificate(nm, ttl)
                doc_bytes, doc_name, doc_ext = st.session_state["demo_cert"], "sertifikat_contoh", "png"

            default_exp = (datetime.now(timezone.utc) + timedelta(days=365)).date()
            exp_date = st.date_input("Masa berlaku dokumen", value=default_exp)
            st.caption("Pilih tanggal yang sudah lewat untuk membuat contoh dokumen berstatus EXPIRED.")
            sign_clicked = st.button("Tandatangani & terbitkan", type="primary", width="stretch")

        with right:
            if doc_bytes:
                st.markdown("**Pratinjau berkas polos**")
                preview(doc_bytes, doc_ext, key="pv_issue_src")

        if sign_clicked:
            if not doc_bytes:
                st.warning("Pilih atau buat berkas sertifikat terlebih dahulu.")
            else:
                try:
                    date_str = exp_date.strftime("%Y-%m-%d")
                    signed, crypto = issue_certificate_file(
                        file_bytes=doc_bytes, file_type=doc_ext, expiry_date_str=date_str,
                        d=keys["d"], n=keys["n"])
                    vhash = compute_sha256(extract_visual_bytes(doc_bytes, doc_ext))
                    st.session_state["issue_result"] = {
                        "signed": signed, "crypto": crypto, "ext": doc_ext, "name": doc_name,
                        "expiry": date_str, "hash": vhash, "orig": doc_bytes, "d": keys["d"], "n": keys["n"],
                        "fp": fingerprint(keys["e"], keys["n"]),
                    }
                    st.session_state["verify_result"] = None
                    st.rerun()
                except Exception as err:
                    st.error(f"Gagal menandatangani sertifikat: {err}")

        ir = st.session_state["issue_result"]
        if ir:
            st.divider()
            cr = ir["crypto"]
            st.markdown(
                '<div class="status-card s-verified"><div class="s-icon">✔</div><div>'
                '<div class="s-title">Sertifikat berhasil ditandatangani</div>'
                f'<div class="s-msg">Segel RSA disuntikkan ke metadata berkas. Tampilan visual tidak berubah. '
                f'Berlaku s.d. {html.escape(ir["expiry"])}.</div></div></div>', unsafe_allow_html=True)
            if keys and ir["fp"] != fingerprint(keys["e"], keys["n"]):
                st.warning("Dokumen ini ditandatangani dengan kunci sebelumnya. Verifikasi dengan kunci publik yang sama.")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Jumlah blok", len(cr["cipher_blocks"]))
            m2.metric("Ukuran chunk (byte)", cr["chunk_size"])
            m3.metric("Panjang token (karakter)", len(cr["token"]))
            m4.metric("Format berkas", ir["ext"].upper())
            st.markdown("**Hash visual dokumen (SHA-256)**")
            st.code(ir["hash"], language="text", wrap_lines=True)
            st.download_button(
                f"⬇ Unduh dokumen bertanda tangan ({ir['ext'].upper()})", data=ir["signed"],
                file_name=f"{ir['name']}_signed.{ir['ext']}",
                mime="application/pdf" if ir["ext"] == "pdf" else "image/png", type="primary")

            pv1, pv2 = st.columns(2)
            with pv1:
                st.markdown("**Sebelum** (polos)")
                preview(ir["orig"], ir["ext"], key="pv_issue_before")
            with pv2:
                st.markdown("**Sesudah** (bertanda tangan, terlihat sama)")
                preview(ir["signed"], ir["ext"], key="pv_issue_after")

            with st.expander("📘 Simulasi perhitungan per blok: m_i → c_i = m_i^d mod n", expanded=True):
                st.caption("Payload `hash|tanggal` dipecah menjadi blok byte, tiap blok dipangkatkan dengan kunci privat d. "
                           "Pilih blok untuk melihat langkah square-and-multiply.")
                nb = len(cr["plain_blocks"])
                idx = st.slider("Blok ke-", 1, nb, 1, key="issue_block_idx") if nb > 1 else 1
                m_i, c_i = cr["plain_blocks"][idx - 1], cr["cipher_blocks"][idx - 1]
                st.write(f"Isi blok (byte → karakter): `{chunk_text(m_i, cr['chunk_size'])}`  ·  m = {m_i}")
                out = render_modpow(m_i, ir["d"], ir["n"], "m", "d", "c")
                st.success(f"c_{idx} = {out}" + ("  ✔ sama dengan token" if out == c_i else "  ✖ berbeda dari token"))

            with st.expander("Seluruh blok & token (/RSA_Token)"):
                st.dataframe([{"blok": i + 1, "m_i": str(m), "karakter": chunk_text(m, cr["chunk_size"]), "c_i": str(c)}
                              for i, (m, c) in enumerate(zip(cr["plain_blocks"], cr["cipher_blocks"]))],
                             hide_index=True, width="stretch")
                st.code(cr["token"], language="text", wrap_lines=True)
            if st.button("Hapus hasil penerbitan"):
                st.session_state["issue_result"] = None
                st.rerun()

# ============================================================================
# TAB 3 - VERIFIKASI
# ============================================================================
with tab_verify:
    st.subheader("Pemeriksaan Keaslian Dokumen (Publik)")
    vl, vr = st.columns([1, 1.2], gap="large")
    with vl:
        options = ["Kunci otoritas sesi ini", "Masukkan kunci publik manual"] if keys else ["Masukkan kunci publik manual"]
        src = st.radio("Kunci publik yang dipakai", options, horizontal=True)
        if src == "Kunci otoritas sesi ini":
            e_txt, n_txt = str(keys["e"]), str(keys["n"])
            st.caption(f"Sidik jari: {fingerprint(keys['e'], keys['n'])}")
        else:
            e_txt = st.text_input("Kunci publik (e)", value="", key="v_e")
            n_txt = st.text_input("Modulus (n)", value="", key="v_n")
        vfile = st.file_uploader("Berkas yang akan diverifikasi (PDF / PNG)", type=["pdf", "png"], key="verify_file")
        run_verify = st.button("Jalankan verifikasi", type="primary", width="stretch")
    with vr:
        if vfile:
            st.markdown("**Pratinjau berkas yang diunggah**")
            preview(vfile.getvalue(), vfile.name.rsplit(".", 1)[-1].lower(), key="pv_verify_upload")

    if run_verify:
        st.session_state["verify_error"] = None
        if not vfile:
            st.session_state["verify_error"] = "Silakan unggah dokumen yang akan diperiksa."
        else:
            try:
                e_int, n_int = parse_int(e_txt, "e"), parse_int(n_txt, "n")
                if e_int < 2 or n_int < 2:
                    raise ValueError("Nilai e dan n tidak valid.")
                vbytes = vfile.getvalue()
                vext = vfile.name.rsplit(".", 1)[-1].lower()
                res = verify_certificate_file(file_bytes=vbytes, file_type=vext, e=e_int, n=n_int)
                st.session_state["verify_result"] = {
                    "res": res, "bytes": vbytes, "ext": vext, "name": vfile.name, "e": e_int, "n": n_int,
                    "token": read_token(vbytes, vext), "file_key": (vfile.name, len(vbytes))}
            except Exception as err:
                st.session_state["verify_result"] = None
                st.session_state["verify_error"] = f"Terjadi kesalahan saat memproses verifikasi: {err}"

    if st.session_state["verify_error"]:
        st.error(st.session_state["verify_error"])

    vr_state = st.session_state["verify_result"]
    if vr_state and vfile and vr_state["file_key"] == (vfile.name, len(vfile.getvalue())):
        res = vr_state["res"]
        st.divider()
        status_card(res["status"], res["message"])
        a, b = st.columns([1, 1.2], gap="large")
        with a:
            st.markdown("**Daftar pemeriksaan**")
            build_checklist(res)
            if res.get("expiry_date"):
                st.metric("Masa berlaku (terbaca dari segel)", res["expiry_date"])
        with b:
            if "current_hash" in res:
                st.markdown("**Perbandingan hash**")
                st.caption("Hash di dalam segel (dipulihkan dengan kunci publik)")
                st.code(res["original_hash"], language="text", wrap_lines=True)
                st.caption("Hash dihitung ulang dari berkas yang diunggah")
                st.code(res["current_hash"], language="text", wrap_lines=True)
                st.error("Berbeda: isi visual dokumen berubah setelah ditandatangani.")
            elif res.get("visual_hash"):
                st.markdown("**Hash dokumen (cocok dengan segel)**")
                st.code(res["visual_hash"], language="text", wrap_lines=True)
                st.success("Hash di dalam segel = hash hasil hitung ulang.")

        st.markdown("**Pratinjau setelah verifikasi**")
        with st.container(border=True):
            label = "Sertifikat resmi" if res["status"] == "VERIFIED" else "Dokumen TIDAK terverifikasi"
            st.caption(f"{label} · {vr_state['name']}")
            preview(vr_state["bytes"], vr_state["ext"], key="pv_verify_result")

        size, c_blocks = parse_token(vr_state["token"]) if vr_state["token"] else (None, [])
        dec = res.get("dec_result") or {}
        if c_blocks and dec.get("decrypted_blocks"):
            with st.expander("📘 Simulasi perhitungan per blok: c_i → m_i = c_i^e mod n", expanded=False):
                st.caption("Tiap blok segel dipangkatkan dengan kunci publik e untuk memulihkan payload `hash|tanggal`.")
                st.dataframe([{"blok": i + 1, "c_i": str(c), "m_i = c_i^e mod n": str(m), "karakter": chunk_text(m, size)}
                              for i, (c, m) in enumerate(zip(c_blocks, dec["decrypted_blocks"]))],
                             hide_index=True, width="stretch")
                nb = len(c_blocks)
                idx = st.slider("Lihat langkah blok ke-", 1, nb, 1, key="verify_block_idx") if nb > 1 else 1
                render_modpow(c_blocks[idx - 1], vr_state["e"], vr_state["n"], "c", "e", "m")
                st.write("Payload pulihan: ", f"`{dec.get('recovered_text')}`")
        elif res["status"] == "TAMPERED" and vr_state["token"]:
            st.caption("Segel tidak dapat didekripsi menjadi payload yang valid, sehingga tabel blok tidak tersedia.")

# ============================================================================
# TAB 4 - ALUR & LAB
# ============================================================================
with tab_learn:
    st.subheader("Alur Sistem")
    c1, c2 = st.columns(2, gap="large")
    with c1:
        with st.container(border=True):
            st.markdown("#### Penerbitan (Issuer)")
            st.markdown(
                "1. Ekstrak konten visual berkas, lalu hitung `visual_hash = SHA-256(visual)`.\n"
                "2. Susun `payload = visual_hash | tanggal_kedaluwarsa`.\n"
                "3. Pecah payload menjadi blok `m_i < n`, lalu tandatangani dengan **kunci privat**:")
            st.latex(r"c_i = m_i^{\,d} \bmod n")
            st.markdown("4. Suntikkan token ke metadata (`/RSA_Token` pada PDF, chunk teks pada PNG).")
    with c2:
        with st.container(border=True):
            st.markdown("#### Verifikasi (Verifier)")
            st.markdown("1. Ambil token dari metadata. Jika tidak ada → **UNSIGNED**.\n"
                        "2. Pulihkan payload dengan **kunci publik**:")
            st.latex(r"m_i = c_i^{\,e} \bmod n")
            st.markdown(
                "3. Format payload rusak → **TAMPERED**.\n"
                "4. Hitung ulang hash visual. Berbeda → **TAMPERED**.\n"
                "5. Tanggal sekarang > kedaluwarsa → **EXPIRED**; selain itu **VERIFIED**.")
    with st.container(border=True):
        st.markdown("#### Pembangkitan kunci")
        st.latex(r"n = p\cdot q \qquad \Phi(n) = (p-1)(q-1) \qquad \gcd(e,\Phi(n)) = 1 \qquad e\cdot d \equiv 1 \pmod{\Phi(n)}")
        st.latex(r"d = \dfrac{1 + k\,\Phi(n)}{e}")
    st.markdown("**Arti status**")
    st.dataframe([
        {"Status": "VERIFIED", "Arti": "Segel valid, hash cocok, masa berlaku aktif"},
        {"Status": "TAMPERED", "Arti": "Segel rusak, kunci publik salah, atau isi visual diubah"},
        {"Status": "EXPIRED", "Arti": "Dokumen otentik, tetapi tanggal kedaluwarsa sudah lewat"},
        {"Status": "UNSIGNED", "Arti": "Berkas biasa tanpa segel RSA"},
    ], hide_index=True, width="stretch")

    st.divider()
    st.subheader("Lab Square-and-Multiply")
    st.caption("Coba hitung sendiri a^b mod n dan lihat tiap langkahnya.")
    lc1, lc2, lc3 = st.columns(3)
    lab_m = lc1.text_input("Basis (m)", "704")
    lab_e = lc2.text_input("Eksponen", "79")
    lab_n = lc3.text_input("Modulus (n)", "3337")
    try:
        bm, be, bn = parse_int(lab_m, "Basis"), parse_int(lab_e, "Eksponen"), parse_int(lab_n, "Modulus")
        if bn < 2:
            raise ValueError("Modulus minimal 2.")
        if be.bit_length() > 4096:
            raise ValueError("Eksponen terlalu besar untuk lab ini.")
        out = render_modpow(bm, be, bn, "a", "b", "r")
        st.success(f"Hasil = {out}  ✔ sama dengan rsa_core.mod_pow")
    except ValueError as err:
        st.warning(str(err))


# ----------------------------------------------------------------------------
# Stepper (dirender terakhir supaya mencerminkan state terbaru pada run ini)
# ----------------------------------------------------------------------------
_done = [bool(st.session_state["rsa_keypair"]), bool(st.session_state["issue_result"]), bool(st.session_state["verify_result"])]
_pills = "".join(
    f'<div class="step-pill {"done" if d else ""}"><span class="dot">{"✔" if d else i + 1}</span>{lbl}</div>'
    for i, (d, lbl) in enumerate(zip(_done, ["Bangkitkan kunci", "Terbitkan & tandatangani", "Verifikasi dokumen"])))
stepper_slot.markdown(f'<div class="stepper">{_pills}</div>', unsafe_allow_html=True)


