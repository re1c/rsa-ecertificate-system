import io
from datetime import datetime, timezone, timedelta
import pytest
from PIL import Image
from PIL.PngImagePlugin import PngInfo
from pypdf import PdfReader, PdfWriter
from rsa_core import generate_keypair
from cert_service import (
    compute_sha256,
    issue_certificate_file,
    verify_certificate_file,
)

# Template minimal PDF valid in-memory
MINIMAL_PDF_BYTES = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] /Contents 4 0 R >>\nendobj\n"
    b"4 0 obj\n<< /Length 39 >>\nstream\nBT\n/F1 12 Tf\n10 10 Td\n(Sertifikat Asli) Tj\nET\nendstream\nendobj\n"
    b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000206 00000 n \n"
    b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n296\n%%EOF"
)


@pytest.fixture
def sample_png_bytes():
    """Menghasilkan dummy gambar PNG in-memory."""
    img = Image.new("RGB", (50, 50), color=(100, 150, 200))
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


@pytest.fixture
def sample_pdf_bytes():
    """Mengembalikan dummy dokumen PDF in-memory."""
    return MINIMAL_PDF_BYTES


@pytest.fixture
def rsa_keys():
    """Menghasilkan pasangan kunci RSA untuk pengujian."""
    return generate_keypair(1009, 1013)


@pytest.fixture
def future_date_str():
    """Tanggal aktif dinamis berbasis UTC (1 tahun ke depan)."""
    return (datetime.now(timezone.utc) + timedelta(days=365)).strftime("%Y-%m-%d")


@pytest.fixture
def past_date_str():
    """Tanggal kedaluwarsa dinamis berbasis UTC (1 hari yang lalu)."""
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def test_hash_computation():
    data = b"Testing SHA256 integrity"
    hash_val = compute_sha256(data)
    assert len(hash_val) == 64
    assert hash_val == compute_sha256(data)


def test_issue_and_verify_png_valid(sample_png_bytes, rsa_keys, future_date_str):
    issued_png, crypto_res = issue_certificate_file(
        file_bytes=sample_png_bytes,
        file_type="png",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    assert len(issued_png) > 0
    assert "token" in crypto_res

    result = verify_certificate_file(
        file_bytes=issued_png,
        file_type="png",
        d=rsa_keys["d"],
        n=rsa_keys["n"],
    )

    assert result["status"] == "VERIFIED"
    assert result["is_valid"] is True
    assert result["expiry_date"] == future_date_str


def test_issue_and_verify_pdf_valid(sample_pdf_bytes, rsa_keys, future_date_str):
    issued_pdf, crypto_res = issue_certificate_file(
        file_bytes=sample_pdf_bytes,
        file_type="pdf",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    assert len(issued_pdf) > 0
    assert "token" in crypto_res

    result = verify_certificate_file(
        file_bytes=issued_pdf,
        file_type="pdf",
        d=rsa_keys["d"],
        n=rsa_keys["n"],
    )

    assert result["status"] == "VERIFIED"
    assert result["is_valid"] is True


def test_unsigned_document_status(sample_png_bytes, sample_pdf_bytes, rsa_keys):
    res_png = verify_certificate_file(sample_png_bytes, "png", rsa_keys["d"], rsa_keys["n"])
    assert res_png["status"] == "UNSIGNED"
    assert res_png["is_valid"] is False

    res_pdf = verify_certificate_file(sample_pdf_bytes, "pdf", rsa_keys["d"], rsa_keys["n"])
    assert res_pdf["status"] == "UNSIGNED"
    assert res_pdf["is_valid"] is False


def test_tampered_visual_png(sample_png_bytes, rsa_keys, future_date_str):
    issued_png, _ = issue_certificate_file(
        file_bytes=sample_png_bytes,
        file_type="png",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    # Modifikasi piksel visual sembari mempertahankan metadata asli
    img = Image.open(io.BytesIO(issued_png))
    img.putpixel((0, 0), (255, 0, 0))
    tampered_buf = io.BytesIO()
    metadata = PngInfo()
    metadata.add_text("RSA_Token", img.text.get("RSA_Token"))
    img.save(tampered_buf, format="PNG", pnginfo=metadata)
    tampered_png = tampered_buf.getvalue()

    result = verify_certificate_file(tampered_png, "png", rsa_keys["d"], rsa_keys["n"])
    assert result["status"] == "TAMPERED"
    assert result["is_valid"] is False


def test_tampered_visual_pdf(sample_pdf_bytes, rsa_keys, future_date_str):
    issued_pdf, _ = issue_certificate_file(
        file_bytes=sample_pdf_bytes,
        file_type="pdf",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    # Menambahkan halaman baru secara terstruktur via pypdf untuk memodifikasi visual
    reader = PdfReader(io.BytesIO(issued_pdf))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_blank_page(width=300, height=200)
    writer.add_metadata(reader.metadata)

    tampered_buf = io.BytesIO()
    writer.write(tampered_buf)
    tampered_pdf = tampered_buf.getvalue()

    result = verify_certificate_file(tampered_pdf, "pdf", rsa_keys["d"], rsa_keys["n"])
    assert result["status"] == "TAMPERED"
    assert result["is_valid"] is False


def test_tampered_token_metadata_png(sample_png_bytes, rsa_keys, future_date_str):
    issued_png, crypto_res = issue_certificate_file(
        file_bytes=sample_png_bytes,
        file_type="png",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    # Visual tidak diubah, namun token di dalam metadata dimanipulasi
    corrupted_token = crypto_res["token"][:-3] + "999"
    img = Image.open(io.BytesIO(issued_png))
    tampered_buf = io.BytesIO()
    metadata = PngInfo()
    metadata.add_text("RSA_Token", corrupted_token)
    img.save(tampered_buf, format="PNG", pnginfo=metadata)
    tampered_png = tampered_buf.getvalue()

    result = verify_certificate_file(tampered_png, "png", rsa_keys["d"], rsa_keys["n"])
    assert result["status"] == "TAMPERED"
    assert result["is_valid"] is False


def test_tampered_token_metadata_pdf(sample_pdf_bytes, rsa_keys, future_date_str):
    issued_pdf, crypto_res = issue_certificate_file(
        file_bytes=sample_pdf_bytes,
        file_type="pdf",
        expiry_date_str=future_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    # Visual tetap asli, tetapi nilai token metadata diubah secara ilegal
    corrupted_token = crypto_res["token"][:-3] + "999"
    reader = PdfReader(io.BytesIO(issued_pdf))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.add_metadata({"/RSA_Token": corrupted_token})

    tampered_buf = io.BytesIO()
    writer.write(tampered_buf)
    tampered_pdf = tampered_buf.getvalue()

    result = verify_certificate_file(tampered_pdf, "pdf", rsa_keys["d"], rsa_keys["n"])
    assert result["status"] == "TAMPERED"
    assert result["is_valid"] is False


def test_expired_certificate(sample_png_bytes, rsa_keys, past_date_str):
    issued_png, _ = issue_certificate_file(
        file_bytes=sample_png_bytes,
        file_type="png",
        expiry_date_str=past_date_str,
        e=rsa_keys["e"],
        n=rsa_keys["n"],
    )

    result = verify_certificate_file(issued_png, "png", rsa_keys["d"], rsa_keys["n"])
    assert result["status"] == "EXPIRED"
    assert result["is_valid"] is False


def test_invalid_expiry_date_format(sample_png_bytes, rsa_keys):
    with pytest.raises(ValueError):
        issue_certificate_file(sample_png_bytes, "png", "31-12-2030", rsa_keys["e"], rsa_keys["n"])


def test_unsupported_file_extension(sample_png_bytes, rsa_keys, future_date_str):
    with pytest.raises(ValueError):
        issue_certificate_file(sample_png_bytes, "docx", future_date_str, rsa_keys["e"], rsa_keys["n"])

