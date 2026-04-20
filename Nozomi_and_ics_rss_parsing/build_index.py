import os
import json
import numpy as np
import faiss
from pathlib import Path
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer

PDF_FOLDER = "rag_docs"
INDEX_FOLDER = "faiss_index"


def chunk_text(text, chunk_size=500, overlap=50):
    words = text.split()
    chunks = []
    i = 0
    while i < len(words):
        chunk = " ".join(words[i : i + chunk_size])
        chunks.append(chunk)
        i += chunk_size - overlap
    return chunks


print("Loading PDFs...")
all_chunks = []
all_metadata = []

for filename in os.listdir(PDF_FOLDER):
    if filename.endswith(".pdf"):
        print(f"  → Reading {filename}")
        reader = PdfReader(os.path.join(PDF_FOLDER, filename))
        for page_num, page in enumerate(reader.pages):
            text = page.extract_text()
            if not text:
                continue
            for chunk in chunk_text(text):
                all_chunks.append(chunk)
                all_metadata.append({"source": filename, "page": page_num + 1})

print(f"\nTotal chunks: {len(all_chunks)}")

print("\nEmbedding chunks (may take a few minutes)...")
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(all_chunks, show_progress_bar=True)
embeddings = np.array(embeddings).astype("float32")

print("\nBuilding FAISS index...")
dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(embeddings)

Path(INDEX_FOLDER).mkdir(exist_ok=True)
faiss.write_index(index, f"{INDEX_FOLDER}/index.faiss")

with open(f"{INDEX_FOLDER}/chunks.json", "w") as f:
    json.dump(all_chunks, f)

with open(f"{INDEX_FOLDER}/metadata.json", "w") as f:
    json.dump(all_metadata, f)

print(f"\n✅ Done! {len(all_chunks)} chunks indexed.")
