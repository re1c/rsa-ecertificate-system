"""
cert_service.py
Service Layer untuk Ekstraksi Hash Dokumen dan Injeksi Metadata RSA
Mendukung format PDF (via pypdf) dan PNG (via Pillow)
"""

import hashlib
import io
from datetime import datetime, timezone
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from pypdf import PdfReader, PdfWriter
import rsa_core


def compute_sha256(data_bytes: bytes) -> str:
    """Menghitung ringkasan SHA-256 dari aliran byte."""
    return hashlib.sha256(data_bytes).hexdigest()


def extract_visual_bytes(file_bytes: bytes, file_type: str) -> bytes:
    """
    Mengekstrak representasi visual dokumen secara deterministik:
    - PDF: Mengikat jumlah halaman, geometri MediaBox, orientasi Rotate,
           aliran konten visual (/Contents), dan data biner gambar (/XObject).
           Metadata dokumen (/Info) diabaikan agar segel /RSA_Token tidak memicu circular collision.
    - PNG: Standardisasi kanonikal ke ruang warna RGBA sebelum ekstraksi biner piksel mentah.
    """
    ext = file_type.lower().lstrip(".")

    if ext == "pdf":
        reader = PdfReader(io.BytesIO(file_bytes))
        visual_stream = bytearray()

        # Ikat struktur dokumen: jumlah halaman
        visual_stream.extend(f"pages:{len(reader.pages)}|".encode("utf-8"))

        for idx, page in enumerate(reader.pages):
            # Ikat geometri dan orientasi kanvas visual
            mediabox_str = str(page.mediabox) if page.mediabox else "default"
            rotate_val = str(page.get("/Rotate", 0))
            visual_stream.extend(f"p{idx}:box:{mediabox_str}:rot:{rotate_val}|".encode("utf-8"))

            contents = page.get_contents()
            if contents is not None:
                if isinstance(contents, list):
                    for c in contents:
                        if hasattr(c, "get_data"):
                            visual_stream.extend(c.get_data())
                elif hasattr(contents, "get_data"):
                    visual_stream.extend(contents.get_data())

            if hasattr(page, "images"):
                for img in page.images:
                    visual_stream.extend(img.data)

        if not visual_stream:
            raise ValueError("Dokumen PDF tidak memuat visual yang dapat diproses.")

        return bytes(visual_stream)

    if ext == "png":
        with Image.open(io.BytesIO(file_bytes)) as img:
            canonical_img = img.convert("RGBA")
            return canonical_img.tobytes()

    raise ValueError(f"Tipe file tidak didukung: {file_type}")


def issue_certificate_file(
    file_bytes: bytes,
    file_type: str,
    expiry_date_str: str,
    e: int,
    n: int
) -> tuple[bytes, dict]:
    """
    Menerbitkan dokumen bersegel:
    1. Validasi format tanggal kedaluwarsa (YYYY-MM-DD).
    2. Ekstrak data visual murni & kalkulasi hash SHA-256.
    3. Susun payload (hash|expiry_date) lalu enkripsi via rsa_core manual.
    4. Suntikkan token ke metadata internal file tanpa merusak visual layer.
    """
    try:
        datetime.strptime(expiry_date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Format tanggal kedaluwarsa harus YYYY-MM-DD.")

    ext = file_type.lower().lstrip(".")
    visual_bytes = extract_visual_bytes(file_bytes, ext)
    visual_hash = compute_sha256(visual_bytes)
    payload = f"{visual_hash}|{expiry_date_str}"

    crypto_result = rsa_core.encrypt_payload(payload, e, n)
    token = crypto_result["token"]

    output_stream = io.BytesIO()

    if ext == "pdf":
        reader = PdfReader(io.BytesIO(file_bytes))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)

        writer.add_metadata({"/RSA_Token": token})
        writer.write(output_stream)

    elif ext == "png":
        with Image.open(io.BytesIO(file_bytes)) as img:
            metadata = PngInfo()
            metadata.add_text("RSA_Token", token)
            img.save(output_stream, format="PNG", pnginfo=metadata)
    else:
        raise ValueError(f"Tipe file tidak didukung: {file_type}")

    return output_stream.getvalue(), crypto_result


def verify_certificate_file(
    file_bytes: bytes,
    file_type: str,
    d: int,
    n: int
) -> dict:
    """
    Memverifikasi status keabsahan dokumen:
    Mengembalikan status: UNSIGNED, TAMPERED, EXPIRED, atau VERIFIED.
    """
    ext = file_type.lower().lstrip(".")
    token = None

    if ext == "pdf":
        reader = PdfReader(io.BytesIO(file_bytes))
        metadata = reader.metadata
        if metadata and "/RSA_Token" in metadata:
            token = metadata["/RSA_Token"]
    elif ext == "png":
        with Image.open(io.BytesIO(file_bytes)) as img:
            token = img.text.get("RSA_Token")
    else:
        raise ValueError(f"Tipe file tidak didukung: {file_type}")

    # 1. Pengecekan keberadaan token
    if not token:
        return {
            "status": "UNSIGNED",
            "message": "Dokumen tidak memiliki token segel resmi.",
            "is_valid": False,
        }

    # 2. Dekripsi matematis RSA manual
    dec_result = rsa_core.decrypt_payload(token, d, n)
    if dec_result["is_corrupted"] or not dec_result["recovered_text"]:
        return {
            "status": "TAMPERED",
            "message": "Token rusak atau gagal didekripsi secara matematis.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    # 3. Parsing aman muatan payload
    try:
        parts = dec_result["recovered_text"].split("|", 1)
        if len(parts) != 2:
            raise ValueError("Struktur pembatas payload tidak sesuai.")
        original_hash, expiry_date_str = parts[0], parts[1]

        if len(original_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in original_hash):
            raise ValueError("Format ringkasan hash dokumen tidak valid.")
    except Exception:
        return {
            "status": "TAMPERED",
            "message": "Format payload di dalam token tidak sesuai spesifikasi.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    # 4. Validasi integritas representasi visual
    current_visual_bytes = extract_visual_bytes(file_bytes, ext)
    current_hash = compute_sha256(current_visual_bytes)

    if current_hash != original_hash:
        return {
            "status": "TAMPERED",
            "message": "Konten visual dokumen telah dimodifikasi setelah diterbitkan.",
            "is_valid": False,
            "current_hash": current_hash,
            "original_hash": original_hash,
            "dec_result": dec_result,
        }

    # 5. Validasi masa berlaku berbasis UTC standar
    try:
        exp_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
        today_utc = datetime.now(timezone.utc).date()
        if today_utc > exp_date:
            return {
                "status": "EXPIRED",
                "message": f"Dokumen sah secara kriptografis tetapi masa berlaku telah habis sejak {expiry_date_str}.",
                "is_valid": False,
                "expiry_date": expiry_date_str,
                "visual_hash": original_hash,
                "dec_result": dec_result,
            }
    except ValueError:
        return {
            "status": "TAMPERED",
            "message": "Format tanggal kedaluwarsa pada token tidak valid.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    return {
        "status": "VERIFIED",
        "message": "Dokumen asli, valid, dan masa berlaku aktif.",
        "is_valid": True,
        "expiry_date": expiry_date_str,
        "visual_hash": original_hash,
        "dec_result": dec_result,
    }
