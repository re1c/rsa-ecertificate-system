
from pypdf import PdfReader

file_path = input("Masukkan path PDF: ")
reader = PdfReader(file_path)

metadata = reader.metadata

print("\n=== METADATA PDF ===")
if metadata:
    for key, value in metadata.items():
        print(f"{key}: {value}")
else:
    print("Tidak ada metadata.")

print("\n=== PEMERIKSAAN RSA TOKEN ===")
if metadata and "/RSA_Token" in metadata:
    token = metadata["/RSA_Token"]
    print("RSA_Token ditemukan!")
    print("Isi token:")
    print(token)
else:
    print("RSA_Token tidak ditemukan pada metadata dokumen.")
