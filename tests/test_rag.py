from shared.rag import chunk_text, SecurityRAG


def test_chunking_overlap():
    chunks = chunk_text("para one.\n\n" + "word " * 300)
    assert len(chunks) >= 1


def test_rag_retrieval():
    rag = SecurityRAG()
    rag.ingest("SQL injection remediation uses parameterised queries.",
               {"title": "sqli"})
    assert "parameterised" in rag.context_for("how to fix sql injection").lower()
