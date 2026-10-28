"""Observe native view results before a blocking reranker, without real models."""

from copy import deepcopy
import json
from threading import Event, Thread

import pytest

from Online.phase2_retrieval import Retriever
from tests.test_online_stages import pipeline  # Reuse the local scripted diagnostic fixture.
from tests.test_retrieval_pipeline import TestRecall as RecallFixture
from tests.offline_fixtures import LocalEmbedding
from utils.runtime_progress import RuntimeProgress


QUERIES = {view: {"view": view, "root_cause": "unchecked input reaches sink"}
           for view in ("data_flow", "control_flow")}


def read(path):
    return json.loads(path.read_text())


def recall_store():
    store, _ = RecallFixture().store()
    # The general ranking fixture has a pre-filled display score; actual offline
    # index metadata is unranked at retrieval time.
    for records in store.metadata.values():
        for record in records:
            record.pop("rerank_score", None)
    return store


def test_observer_has_complete_views_without_changing_native_results():
    store = recall_store()
    retriever = Retriever(store, LocalEmbedding())
    original = retriever.retrieve(QUERIES)
    snapshots = []

    def observer(view, candidates):
        snapshots.append((view, deepcopy(candidates)))
        # Deliberately corrupt the observer's copy. Neither later snapshots nor
        # the returned ranking inputs may change.
        candidates[0]["retrieval_hits"].clear()
        candidates.clear()

    observed = retriever.retrieve(QUERIES, on_view=observer)
    assert observed == original
    assert [view for view, _ in snapshots] == ["data_flow", "control_flow"]
    assert len(snapshots[0][1]) == 10 and len(snapshots[1][1]) == 12
    assert {hit["query_view"] for item in snapshots[0][1] for hit in item["retrieval_hits"]} == {"data_flow"}
    assert snapshots[1][1] == original


def test_observer_failure_is_explicit():
    store = recall_store()
    def broken(*args):
        raise RuntimeError("progress could not be written")
    with pytest.raises(RuntimeError, match="progress could not be written"):
        Retriever(store, LocalEmbedding()).retrieve(QUERIES, on_view=broken)


def test_empty_view_is_still_observed_as_completed():
    store = recall_store()
    store.search = lambda *args, **kwargs: ([], [])
    calls = []
    assert Retriever(store, LocalEmbedding()).retrieve(
        QUERIES, on_view=lambda view, rows: calls.append((view, rows))) == []
    assert calls == [("data_flow", []), ("control_flow", [])]


def test_partial_is_visible_while_reranker_blocks_and_final_stays_native(pipeline):
    pipeline.run("diagnosis")
    store = recall_store()
    retriever = Retriever(store, LocalEmbedding())
    native = retriever.retrieve(QUERIES)
    pipeline.models["retriever"] = retriever
    pipeline.models["query_generator"].generate_queries.return_value = QUERIES
    started, release = Event(), Event()
    finished, errors = [], []
    runtime = RuntimeProgress(pipeline.store.root / "progress.json", stage="retrieval",
                              execution_id="test-execution", run_id=pipeline.store.run_id)

    def blocked(report, source, candidates, top_k):
        assert candidates == native
        started.set()
        assert release.wait(5), "Test did not release mock reranker"
        return candidates[:top_k]

    pipeline.models["reranker"].rerank.side_effect = blocked

    def worker():
        try:
            with runtime.activate():
                finished.append(pipeline.run("retrieval"))
        except BaseException as error:
            errors.append(error)

    thread = Thread(target=worker)
    thread.start()
    try:
        assert started.wait(5)
        partial = read(pipeline.case / "retrieval_progress.json")
        assert partial["status"] == "running" and partial["step"] == "reranking"
        assert partial["execution_id"] == "test-execution"
        assert partial["queries"] == QUERIES
        assert partial["completed_views"] == ["data_flow", "control_flow"]
        assert partial["candidates"] == native
        assert "final_exemplars" not in partial
        assert all("rerank_score" not in item for item in partial["candidates"])
        assert not (pipeline.case / "retrieval.json").exists()
        progress = read(pipeline.store.root / "progress.json")
        assert progress["step"] == "reranking" and progress["status"] == "running"
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive() and not errors
    assert finished[0]["status"] == "retrieval_ready"
    assert read(pipeline.case / "retrieval_progress.json")["status"] == "completed"
    final = read(pipeline.case / "retrieval.json")
    assert [item["sample_id"] for item in final["final_exemplars"]] == [item["sample_id"] for item in native[:4]]
    assert "execution_id" not in final and "completed_views" not in final


def test_failed_reranking_keeps_unranked_results_and_query_before_retrieval(pipeline):
    pipeline.run("diagnosis")
    pipeline.models["query_generator"].generate_queries.return_value = QUERIES

    def retrieve(queries):
        # Backwards-compatible retrievers without on_view see a saved query
        # before any actual retrieval work starts.
        partial = read(pipeline.case / "retrieval_progress.json")
        assert partial["queries"] == queries and partial["step"] == "retrieval"
        assert partial["candidates"] == []
        return [{"sample_id": "native"}]

    pipeline.models["retriever"].retrieve = retrieve
    pipeline.models["reranker"].rerank.side_effect = ValueError("encoder failed")
    with pytest.raises(ValueError, match="encoder failed"):
        pipeline.run("retrieval")
    partial = read(pipeline.case / "retrieval_progress.json")
    assert partial["status"] == "failed" and partial["step"] == "reranking"
    assert partial["candidates"] == [{"sample_id": "native"}]
    assert not (pipeline.case / "retrieval.json").exists()


def test_retrieval_type_error_is_not_retried_with_a_different_signature(pipeline):
    pipeline.run("diagnosis")
    calls = []
    def retrieve(queries, *, on_view=None):
        calls.append(queries)
        raise TypeError("actual retrieval bug")
    pipeline.models["retriever"].retrieve = retrieve
    with pytest.raises(TypeError, match="actual retrieval bug"):
        pipeline.run("retrieval")
    assert len(calls) == 1
    assert read(pipeline.case / "retrieval_progress.json")["step"] == "retrieval"
