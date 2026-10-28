"""Explicit source selection with original-file coordinates preserved."""

import hashlib


def select_source_context(code, settings=None):
    settings = settings or {"strategy": "full"}
    lines = code.splitlines(keepends=True)
    total = len(lines)
    strategy = settings.get("strategy", "full")
    if strategy == "full":
        start, end, provenance = 1, total, "complete_source"
    elif strategy == "line_range":
        start, end = settings["start_line"], settings["end_line"]
        provenance = settings["line_hint_source"]
        if (
            type(start) is not int
            or type(end) is not int
            or not 1 <= start <= end <= total
            or not isinstance(provenance, str)
            or not provenance.strip()
        ):
            raise ValueError(
                "Explicit source range and its line_hint_source must be valid"
            )
    else:
        raise ValueError("Source strategy must be full or line_range")
    crlf = code.count("\r\n")
    bare_lf = code.count("\n") - crlf
    bare_cr = code.count("\r") - crlf
    endings = (
        "mixed"
        if sum(bool(count) for count in (crlf, bare_lf, bare_cr)) > 1
        else "crlf" if crlf else "lf" if bare_lf else "cr" if bare_cr else "none"
    )
    context = dict(
        line_ending_style=endings,
        final_newline=code.endswith(("\n", "\r")),
        strategy=strategy,
        selection_source=provenance,
        total_lines=total,
        window_active=strategy != "full",
        window_start=start,
        window_end=end,
        window_offset=start - 1,
        window_line_count=max(0, end - start + 1),
        display_line_numbers="original_file",
        diff_line_numbers="original_file",
        original_sha256=hashlib.sha256(code.encode()).hexdigest(),
    )
    return "".join(lines[start - 1 : end]), context


def numbered_source(code, context=None):
    if context is None:
        _, context = select_source_context(code)
    lines = code.splitlines()
    return "\n".join(
        f"{index}: {lines[index - 1]}"
        for index in range(context["window_start"], context["window_end"] + 1)
    )
