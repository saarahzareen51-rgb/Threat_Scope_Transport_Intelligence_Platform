import os
import json
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

# Always find faiss_index relative to THIS file's location
# regardless of where Streamlit is launched from
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FOLDER = os.path.join(BASE_DIR, "faiss_index")

print("Loading FAISS index...")
_model = SentenceTransformer("all-MiniLM-L6-v2")
_index = faiss.read_index(os.path.join(INDEX_FOLDER, "index.faiss"))

with open(os.path.join(INDEX_FOLDER, "chunks.json"), "r") as f:
    _chunks = json.load(f)

with open(os.path.join(INDEX_FOLDER, "metadata.json"), "r") as f:
    _metadata = json.load(f)

print(f"✅ FAISS index loaded. {len(_chunks)} chunks ready.")


def retrieve_context(query: str, k: int = 3) -> str:
    query_embedding = _model.encode([query])
    query_embedding = np.array(query_embedding).astype("float32")

    distances, indices = _index.search(query_embedding, k)

    context_parts = []
    for i, idx in enumerate(indices[0]):
        if idx == -1:
            continue
        chunk = _chunks[idx]
        meta = _metadata[idx]
        source = meta.get("source", "Unknown")
        page = meta.get("page", "?")
        context_parts.append(f"[Source {i+1}: {source}, p.{page}]\n{chunk.strip()}")

    return "\n\n".join(context_parts)
