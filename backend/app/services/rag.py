import hashlib
import math
from app.db import CHROMA_DIR
from app.services.knowledge import FORENSIC_KB

_client = None


class HashEmbeddingFunction:
    """Offline stand-in for UAE_Large-V1 / MiniLM when models cannot be downloaded."""

    def __call__(self, input):
        vecs = []
        for text in input:
            h = hashlib.sha256(text.lower().encode()).digest()
            # expand with overlapping hashes for a 384-d-ish vector
            raw = h
            seed = text.lower()
            while len(raw) < 384:
                seed = hashlib.sha256(seed.encode() if isinstance(seed, str) else seed).hexdigest()
                raw += hashlib.sha256(seed.encode()).digest()
            vals = [(b - 128) / 128.0 for b in raw[:384]]
            n = math.sqrt(sum(v * v for v in vals)) or 1.0
            vecs.append([v / n for v in vals])
        return vecs

    def name(self):
        return "hash-embed-v1"


def _get_client():
    global _client
    if _client is None:
        import chromadb

        _client = chromadb.PersistentClient(path=CHROMA_DIR)
    return _client


def _ef():
    return HashEmbeddingFunction()


def knowledge_collection():
    client = _get_client()
    col = client.get_or_create_collection(
        "forensic_knowledge",
        embedding_function=_ef(),
        metadata={"hnsw:space": "cosine"},
    )
    if col.count() == 0:
        col.add(ids=[d["id"] for d in FORENSIC_KB], documents=[d["text"] for d in FORENSIC_KB])
    return col


def case_collection(case_id: int):
    client = _get_client()
    return client.get_or_create_collection(
        f"case_{case_id}",
        embedding_function=_ef(),
        metadata={"hnsw:space": "cosine"},
    )


def index_case_events(case_id: int, events: list[dict]):
    try:
        _get_client().delete_collection(f"case_{case_id}")
    except Exception:
        pass
    col = case_collection(case_id)
    ids, docs, metas = [], [], []
    for i, ev in enumerate(events):
        ids.append(f"ev-{ev.get('id', i)}")
        docs.append(
            f"{ev.get('timestamp')} [{ev.get('source_type')}/{ev.get('event_type')}] "
            f"{ev.get('description')} actor={ev.get('actor')} target={ev.get('target')}"
        )
        metas.append({"artifact_id": str(ev.get("id", i)), "source_type": ev.get("source_type") or ""})
    if ids:
        col.add(ids=ids, documents=docs, metadatas=metas)
    return len(ids)


def _keyword_rank(docs: list[str], query: str, k: int) -> list[str]:
    toks = {t for t in query.lower().replace("/", " ").split() if len(t) > 2}
    scored = []
    for d in docs:
        low = d.lower()
        score = sum(1 for t in toks if t in low)
        scored.append((score, d))
    scored.sort(key=lambda x: -x[0])
    return [d for s, d in scored if s > 0][:k] or [d for _, d in scored[:k]]


def retrieve(case_id: int, query: str, k: int = 6) -> dict:
    knowledge = _keyword_rank([d["text"] for d in FORENSIC_KB], query, k)
    evidence, metas = [], []
    try:
        cs = case_collection(case_id)
        if cs.count():
            got = cs.get()
            docs = got.get("documents") or []
            evidence = _keyword_rank(docs, query, k)
    except Exception:
        evidence = []
    return {"knowledge": knowledge, "evidence": evidence, "metas": metas}
