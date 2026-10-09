"""
cert_service.py
Service Layer untuk Ekstraksi Hash Dokumen dan Penandatanganan Digital RSA
Mendukung format PDF (via pypdf) dan PNG (via Pillow)
"""

import hashlib
import io
from datetime import datetime, timezone
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from pypdf import PdfReader, PdfWriter
import fitz  # PyMuPDF: render PDF pages to their visible appearance
import rsa_core


def compute_sha256(data_bytes: bytes) -> str:
    """Menghitung ringkasan SHA-256 dari aliran byte."""
    return hashlib.sha256(data_bytes).hexdigest()


def extract_visual_bytes(file_bytes: bytes, file_type: str) -> bytes:
    """Return a deterministic representation of the document's visible content.

    - PDF: render every page with fixed settings and hash the rendered RGB pixels.
      Page annotations are rendered too, so visible markup/images are included.
      PDF metadata is not part of this representation, avoiding a token/hash loop.
    - PNG: convert to RGBA and return raw pixel bytes.
    """
    ext = file_type.lower().lstrip(".")

    if ext == "pdf":
        try:
            document = fitz.open(stream=file_bytes, filetype="pdf")
        except Exception as exc:
            raise ValueError("Dokumen PDF tidak dapat dibaca atau dirender.") from exc

        if document.needs_pass:
            document.close()
            raise ValueError("PDF terenkripsi dengan kata sandi tidak didukung.")
        if len(document) == 0:
            document.close()
            raise ValueError("Dokumen PDF tidak memiliki halaman.")

        # A fixed 2x matrix (144 DPI at PDF's 72-point base) and RGB/no-alpha
        # make rendering consistent between signing and verification.
        matrix = fitz.Matrix(2, 2)
        visual_stream = bytearray(b"PDF-RENDER-RGB-v1\0")
        try:
            for idx, page in enumerate(document):
                pix = page.get_pixmap(
                    matrix=matrix,
                    colorspace=fitz.csRGB,
                    alpha=False,
                    annots=True,
                )
                # Add page index and dimensions to prevent ambiguous concatenation.
                visual_stream.extend(
                    f"page:{idx};width:{pix.width};height:{pix.height};channels:{pix.n}\0".encode("ascii")
                )
                visual_stream.extend(pix.samples)
                visual_stream.extend(b"\0END-PAGE\0")
        except Exception as exc:
            raise ValueError("Gagal merender tampilan visual dokumen PDF.") from exc
        finally:
            document.close()

        return bytes(visual_stream)

    if ext == "png":
        with Image.open(io.BytesIO(file_bytes)) as img:
            canonical_img = img.convert("RGBA")
            # Include dimensions and a format marker to make the representation unambiguous.
            header = f"PNG-RGBA-v1;width:{canonical_img.width};height:{canonical_img.height}\0".encode("ascii")
            return header + canonical_img.tobytes()

    raise ValueError(f"Tipe file tidak didukung: {file_type}")


def issue_certificate_file(
    file_bytes: bytes,
    file_type: str,
    expiry_date_str: str,
    d: int,
    n: int
) -> tuple[bytes, dict]:
    """
    Menerbitkan dokumen bertanda tangan digital:
    Menggunakan KUNCI PRIVAT (d, n) milik otoritas penerbit.
    """
    try:
        datetime.strptime(expiry_date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError("Format tanggal kedaluwarsa harus YYYY-MM-DD.")

    ext = file_type.lower().lstrip(".")
    visual_bytes = extract_visual_bytes(file_bytes, ext)
    visual_hash = compute_sha256(visual_bytes)
    payload = f"{visual_hash}|{expiry_date_str}"

    # Penandatanganan digital: c = m^d mod n
    crypto_result = rsa_core.encrypt_payload(payload, d, n)
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
    e: int,
    n: int
) -> dict:
    """
    Memverifikasi keabsahan tanda tangan digital dokumen:
    Menggunakan KUNCI PUBLIK (e, n) milik otoritas penerbit.
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

    if not token:
        return {
            "status": "UNSIGNED",
            "message": "Dokumen tidak memiliki segel tanda tangan digital.",
            "is_valid": False,
        }

    # Verifikasi tanda tangan: m = c^e mod n
    dec_result = rsa_core.decrypt_payload(token, e, n)
    if dec_result["is_corrupted"] or not dec_result["recovered_text"]:
        return {
            "status": "TAMPERED",
            "message": "Tanda tangan rusak atau tidak valid secara matematis.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    try:
        parts = dec_result["recovered_text"].split("|", 1)
        if len(parts) != 2:
            raise ValueError("Struktur payload tanda tangan tidak valid.")
        original_hash, expiry_date_str = parts[0], parts[1]

        if len(original_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in original_hash):
            raise ValueError("Format ringkasan hash dokumen tidak valid.")
    except Exception:
        return {
            "status": "TAMPERED",
            "message": "Format payload tanda tangan tidak sesuai spesifikasi.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    current_visual_bytes = extract_visual_bytes(file_bytes, ext)
    current_hash = compute_sha256(current_visual_bytes)

    if current_hash != original_hash:
        return {
            "status": "TAMPERED",
            "message": "Konten visual dokumen telah dimodifikasi setelah ditandatangani.",
            "is_valid": False,
            "current_hash": current_hash,
            "original_hash": original_hash,
            "dec_result": dec_result,
        }

    try:
        exp_date = datetime.strptime(expiry_date_str, "%Y-%m-%d").date()
        today_utc = datetime.now(timezone.utc).date()
        if today_utc > exp_date:
            return {
                "status": "EXPIRED",
                "message": f"Tanda tangan otentik tetapi masa berlaku dokumen telah habis sejak {expiry_date_str}.",
                "is_valid": False,
                "expiry_date": expiry_date_str,
                "visual_hash": original_hash,
                "dec_result": dec_result,
            }
    except ValueError:
        return {
            "status": "TAMPERED",
            "message": "Format tanggal kedaluwarsa pada tanda tangan tidak valid.",
            "is_valid": False,
            "dec_result": dec_result,
        }

    return {
        "status": "VERIFIED",
        "message": "Dokumen asli, tanda tangan sah, dan masa berlaku aktif.",
        "is_valid": True,
        "expiry_date": expiry_date_str,
        "visual_hash": original_hash,
        "dec_result": dec_result,
    }
