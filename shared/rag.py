"""Retrieval-Augmented Generation over a security knowledge base using ChromaDB.

Knowledge base = CVE notes, remediation playbooks, and compliance mappings.
Demonstrates chunking strategy + vector retrieval + graceful offline fallback.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from shared.config import get_settings
from observability.logging import get_logger

logger = get_logger(__name__)

COLLECTION = "security_kb"


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 80) -> list[str]:
    """Recursive-ish char chunker with overlap (paragraph-aware)."""
    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if len(buf) + len(p) + 2 <= chunk_size:
            buf = f"{buf}\n\n{p}".strip()
        else:
            if buf:
                chunks.append(buf)
            # keep overlap tail for context continuity
            buf = (buf[-overlap:] + "\n\n" + p) if buf else p
            while len(buf) > chunk_size:
                chunks.append(buf[:chunk_size])
                buf = buf[chunk_size - overlap:]
    if buf:
        chunks.append(buf)
    return chunks


class _FallbackStore:
    """In-memory TF-ish store used when chromadb is unavailable (offline/tests)."""
    def __init__(self):
        self.docs: list[tuple[str, dict]] = []

    def add(self, texts, metadatas):
        self.docs.extend(zip(texts, metadatas))

    def query(self, text, k):
        terms = set(text.lower().split())
        scored = []
        for doc, meta in self.docs:
            score = len(terms & set(doc.lower().split()))
            scored.append((score, doc, meta))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [(d, m) for _, d, m in scored[:k]]


class SecurityRAG:
    def __init__(self):
        self._fallback: Optional[_FallbackStore] = None
        self._collection = None
        s = get_settings()
        try:
            import chromadb
            client = chromadb.PersistentClient(path=s.chroma_dir)
            self._collection = client.get_or_create_collection(COLLECTION)
            logger.info("rag.chroma_ready")
        except Exception as exc:
            logger.warning("rag.fallback", extra={"err": str(exc)})
            self._fallback = _FallbackStore()

    def ingest(self, text: str, metadata: dict) -> int:
        chunks = chunk_text(text)
        metas = [{**metadata, "chunk": i} for i in range(len(chunks))]
        if self._collection is not None:
            ids = [hashlib.md5(f"{metadata}-{i}-{c[:20]}".encode()).hexdigest()
                   for i, c in enumerate(chunks)]
            self._collection.upsert(documents=chunks, metadatas=metas, ids=ids)
        else:
            self._fallback.add(chunks, metas)
        return len(chunks)

    def retrieve(self, query: str, k: int = 3) -> list[dict]:
        if self._collection is not None:
            res = self._collection.query(query_texts=[query], n_results=k)
            docs = res.get("documents", [[]])[0]
            metas = res.get("metadatas", [[]])[0]
            return [{"text": d, "meta": m} for d, m in zip(docs, metas)]
        return [{"text": d, "meta": m} for d, m in self._fallback.query(query, k)]

    def context_for(self, query: str, k: int = 3) -> str:
        hits = self.retrieve(query, k)
        return "\n---\n".join(h["text"] for h in hits) if hits else "(no KB context)"


def seed_knowledge_base(rag: SecurityRAG) -> None:
    """Load the sample security KB from data/ into the vector store."""
    import json
    import pathlib
    path = pathlib.Path("data/knowledge_base.json")
    if not path.exists():
        logger.warning("rag.no_seed_file")
        return
    for item in json.loads(path.read_text(encoding="utf-8")):
        rag.ingest(item["content"], {"title": item["title"],
                                     "source": item.get("source", "kb")})
    logger.info("rag.seeded")
