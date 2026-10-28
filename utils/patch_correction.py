"""Bounded context edit-distance alignment for a complete single-target diff.

Only unchanged context and coordinates may be corrected. Added/deleted rows,
including their newline markers, are immutable. Minimum context edit distance
wins, followed by distance to the declared source range; unresolved semantic
placement ties reject the whole candidate.
"""

from collections import defaultdict
from dataclasses import dataclass, replace
import hashlib
import json
import re


ALGORITHM = "context_edit_distance_v1"
MAX_DP_CELLS = 2_000_000
MAX_HUNK_ROWS = 512
MAX_CONTEXT_EDITS = 8
MAX_HUNKS = 128
HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@([^\r\n]*)(?:\r?\n)?$")
NO_NEWLINE = "\\ No newline at end of file"


@dataclass(frozen=True)
class Row:
    kind: str
    text: str
    raw: str


@dataclass(frozen=True)
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    suffix: str
    newline: str
    rows: tuple

    @property
    def offset(self):
        return self.old_start - 1 if self.old_count else self.old_start

    def ranges(self):
        return dict(old_start=self.old_start, old_count=self.old_count,
                    new_start=self.new_start, new_count=self.new_count)


def parse_diff(patch):
    """Parse complete hunks; inconsistent counts cannot be guessed safely."""
    lines = patch.splitlines(keepends=True)
    index = next((i for i, line in enumerate(lines) if line.startswith("@@ ")), len(lines))
    prefix, hunks = "".join(lines[:index]), []
    if index == len(lines):
        raise ValueError("Patch contains no unified diff hunks")
    while index < len(lines):
        match = HEADER.fullmatch(lines[index])
        if not match:
            raise ValueError("Expected a complete hunk; extra files/content are unsupported")
        old, count, new, new_count, suffix = match.groups()
        count, new_count = 1 if count is None else int(count), 1 if new_count is None else int(new_count)
        newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
        index += 1
        rows, consumed, produced = [], 0, 0
        while consumed < count or produced < new_count:
            if index >= len(lines) or lines[index][:1] not in {" ", "+", "-"}:
                raise ValueError("Incomplete diff hunk or inconsistent line counts")
            raw = lines[index]
            kind, content = raw[0], raw[1:]
            index += 1
            if index < len(lines) and lines[index].rstrip("\r\n") == NO_NEWLINE:
                content = content.rstrip("\r\n")
                raw += lines[index]
                index += 1
            rows.append(Row(kind, content, raw))
            consumed += kind in {" ", "-"}
            produced += kind in {" ", "+"}
            if consumed > count or produced > new_count:
                raise ValueError("Diff hunk line counts are inconsistent")
        if not any(row.kind in {"+", "-"} for row in rows):
            raise ValueError("Each hunk must contain an addition or deletion")
        hunks.append(Hunk(int(old), count, int(new), new_count, suffix, newline, tuple(rows)))
    return prefix, hunks


def edit_fingerprint(hunks):
    # Include physical row bytes as well as logical no-newline semantics.
    edits = [[(row.kind, row.text, row.raw) for row in hunk.rows if row.kind in {"+", "-"}] for hunk in hunks]
    return hashlib.sha256(json.dumps(edits, ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(slots=True)
class State:
    cost: int
    start: int
    signature: int
    previous: object = None
    operation: tuple | None = None
    ambiguous: bool = False


@dataclass
class Placement:
    start: int
    end: int
    rows: tuple
    cost: int
    edits: tuple
    operations: list
    ambiguous: bool = False


class Budget:
    def __init__(self):
        self.cells = 0
        self.comparisons = 0

    def check(self):
        if self.cells + self.comparisons > MAX_DP_CELLS:
            raise ValueError("Patch correction exceeded its dynamic-programming cell budget")

    def consume(self, rows, columns):
        self.cells += rows * columns
        self.check()

    def matches(self, source, start, old):
        for index, row in enumerate(old):
            self.comparisons += 1
            self.check()
            if source[start + index] != row:
                return False
        return True


def _context(text):
    return Row(" ", text, " " + text if text.endswith(("\n", "\r")) else " " + text + "\n" + NO_NEWLINE + "\n")


def _align(source, hunk, anchor_row, anchor_position, lower, upper, edits_limit, budget):
    old_before = sum(row.kind != "+" for row in hunk.rows[:anchor_row])
    begin = max(lower, anchor_position - old_before - edits_limit)
    end = min(upper, anchor_position + hunk.old_count - old_before + edits_limit)
    window = source[begin:end]
    budget.consume(len(hunk.rows) + 1, len(window) + 1)
    signatures, signature_ids = [()], {}

    def signature(previous, kind, row, position):
        key = previous, kind, row, position
        if key not in signature_ids:
            signature_ids[key] = len(signatures)
            signatures.append(signatures[previous] + ((kind, row, position),))
        return signature_ids[key]

    def choose(candidates):
        candidates = [state for state in candidates if state.cost <= edits_limit]
        if not candidates:
            return None
        key = lambda state: (state.cost, abs(state.start - hunk.offset))
        best = min(candidates, key=lambda state: (key(state), state.start))
        tied = [state for state in candidates if key(state) == key(best)]
        ambiguous = any(state.ambiguous or state.signature != best.signature for state in tied)
        return replace(best, ambiguous=ambiguous)

    previous = [State(0, begin + j, 0) for j in range(len(window) + 1)]
    for i, row in enumerate(hunk.rows):
        current = [None] * (len(window) + 1)
        for j in range(len(window) + 1):
            candidates = []
            above = previous[j]
            if above is not None:
                if row.kind == "+":
                    candidates.append(State(above.cost, above.start,
                                            signature(above.signature, "+", i, begin + j),
                                            above, ("add", i, begin + j), above.ambiguous))
                elif row.kind == " " and i != anchor_row:
                    candidates.append(State(above.cost + 1, above.start, above.signature,
                                            above, ("drop_context", i, begin + j), above.ambiguous))
            if j and previous[j - 1] is not None and row.kind != "+":
                diagonal = previous[j - 1]
                equal = row.text == window[j - 1]
                anchored = i != anchor_row or begin + j - 1 == anchor_position and equal
                if anchored and (equal or row.kind == " "):
                    cost = diagonal.cost + (not equal)
                    sig = signature(diagonal.signature, "-", i, begin + j - 1) if row.kind == "-" else diagonal.signature
                    operation = "delete" if row.kind == "-" else "context" if equal else "replace_context"
                    candidates.append(State(cost, diagonal.start, sig, diagonal,
                                            (operation, i, begin + j - 1), diagonal.ambiguous))
            # Actual source lines missing from the model's context remain unchanged.
            if j and i + 1 < len(hunk.rows) and current[j - 1] is not None:
                left = current[j - 1]
                candidates.append(State(left.cost + 1, left.start, left.signature, left,
                                        ("insert_context", i, begin + j - 1), left.ambiguous))
            current[j] = choose(candidates)
        previous = current
    placements = []
    for j, state in enumerate(previous):
        if state is None:
            continue
        steps, cursor = [], state
        while cursor.previous is not None:
            steps.append(cursor.operation)
            cursor = cursor.previous
        rows, changes = [], []
        for operation, index, position in reversed(steps):
            if operation in {"add", "delete"}:
                rows.append(hunk.rows[index])
            elif operation in {"context", "replace_context", "insert_context"}:
                rows.append(_context(source[position]))
            if operation in {"replace_context", "insert_context", "drop_context"}:
                changes.append(dict(operation=operation, original_row=index + 1, source_line=position + 1))
        placements.append(Placement(state.start, begin + j, tuple(rows), state.cost,
                                    signatures[state.signature], changes, state.ambiguous))
    return placements


def _place(source, hunk, positions, lower, upper, budget):
    if len(hunk.rows) > MAX_HUNK_ROWS:
        raise ValueError("Patch correction exceeded its hunk-row budget")
    old = [row.text for row in hunk.rows if row.kind != "+"]
    if lower <= hunk.offset <= upper and hunk.offset + len(old) <= upper:
        if source[hunk.offset:hunk.offset + len(old)] == old:
            return Placement(hunk.offset, hunk.offset + len(old), hunk.rows, 0, (), [])
    if not old:
        raise ValueError("A context-free insertion has no valid original coordinate")
    anchors = [(index, row) for index, row in enumerate(hunk.rows) if row.kind == "-"]
    if anchors:
        if any(not positions.get(row.text) for _, row in anchors):
            raise ValueError("Deleted content does not occur exactly in the supplied source")
    else:
        anchors = [(index, row) for index, row in enumerate(hunk.rows) if row.kind == " " and positions.get(row.text)]
    if not anchors:
        raise ValueError("No exact deletion/context anchor can locate this hunk")
    ordered_anchors = sorted(anchors, key=lambda item: (len(positions[item[1].text]), item[0]))
    anchor_index, anchor = ordered_anchors[0]
    old_before = sum(row.kind != "+" for row in hunk.rows[:anchor_index])
    exact = []
    for position in positions[anchor.text]:
        start = position - old_before
        if lower <= start and start + len(old) <= upper and budget.matches(source, start, old):
            exact.append(start)
    if exact:
        distance = min(abs(start - hunk.offset) for start in exact)
        nearest = [start for start in exact if abs(start - hunk.offset) == distance]
        if len(nearest) != 1:
            raise ValueError("Hunk placement is ambiguous after edit-distance and coordinate tie-breaking")
        return Placement(nearest[0], nearest[0] + len(old), hunk.rows, 0, (), [])
    contexts = sum(row.kind == " " for row in hunk.rows)
    limit = min(MAX_CONTEXT_EDITS, max(1, contexts // 3))
    best, best_key = None, None
    # Every deletion is immutable, so any one of them is a mandatory anchor.
    # With additions only, a context row may itself be hallucinated: try all
    # exact context anchors rather than forcing the rarest row to be correct.
    for anchor_index, anchor in ordered_anchors[:1] if any(row.kind == "-" for row in hunk.rows) else ordered_anchors:
        old_before = sum(row.kind != "+" for row in hunk.rows[:anchor_index])
        occurrences = sorted((position for position in positions[anchor.text] if lower <= position < upper),
                             key=lambda position: (abs(position - old_before - hunk.offset), position))
        for position in occurrences:
            for candidate in _align(source, hunk, anchor_index, position, lower, upper, limit, budget):
                key = (candidate.cost, abs(candidate.start - hunk.offset),
                       abs(candidate.end - (hunk.offset + hunk.old_count)))
                if best_key is None or key < best_key:
                    best, best_key = candidate, key
                elif key == best_key:
                    ambiguous = best.ambiguous or candidate.ambiguous or best.edits != candidate.edits
                    if (candidate.start, candidate.end) < (best.start, best.end):
                        best = candidate
                    best.ambiguous = ambiguous
    if best is None:
        raise ValueError("No complete hunk alignment fits the context-edit budget")
    if best.ambiguous:
        raise ValueError("Hunk placement is ambiguous after edit-distance and coordinate tie-breaking")
    return best


def correct_diff(original, patch, source_context=None):
    prefix, hunks = parse_diff(patch)
    if len(hunks) > MAX_HUNKS:
        raise ValueError("Patch correction exceeded its hunk-count budget")
    source = original.splitlines(keepends=True)
    lower, upper = 0, len(source)
    if source_context and source_context.get("window_active"):
        lower, upper = source_context["window_start"] - 1, source_context["window_end"]
    if not 0 <= lower <= upper <= len(source):
        raise ValueError("Patch correction has an invalid source-window boundary")
    positions = defaultdict(list)
    for index in range(lower, upper):
        positions[source[index]].append(index)
    output, reports, cursor, delta, budget = [prefix], [], lower, 0, Budget()
    for number, hunk in enumerate(hunks, 1):
        placement = _place(source, hunk, positions, lower, upper, budget)
        if placement.start < cursor:
            raise ValueError("Corrected hunks overlap or are out of original-source order")
        old_count = sum(row.kind != "+" for row in placement.rows)
        new_count = sum(row.kind != "-" for row in placement.rows)
        old_start = placement.start + (1 if old_count else 0)
        new_start = placement.start + delta + (1 if new_count else 0)
        output.append(f"@@ -{old_start},{old_count} +{new_start},{new_count} @@{hunk.suffix}{hunk.newline}")
        output.extend(row.raw for row in placement.rows)
        corrected = dict(old_start=old_start, old_count=old_count, new_start=new_start, new_count=new_count)
        reports.append(dict(hunk=number, original=hunk.ranges(), corrected=corrected,
                            edit_distance=placement.cost, context_changes=placement.operations))
        delta += new_count - old_count
        cursor = placement.end
    corrected = "".join(output)
    if edit_fingerprint(hunks) != edit_fingerprint(parse_diff(corrected)[1]):
        raise ValueError("Correction changed candidate additions/deletions or hunk grouping")
    return corrected, reports, dict(dp_cells=budget.cells, source_line_comparisons=budget.comparisons,
                                    max_work_units=MAX_DP_CELLS,
                                    max_hunk_rows=MAX_HUNK_ROWS, max_context_edits=MAX_CONTEXT_EDITS,
                                    max_hunks=MAX_HUNKS)
