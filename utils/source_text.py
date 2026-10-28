"""Explicit text preparation for known Latin-1 benchmark comments."""

import inspect


def latin1_comments_to_utf8(data):
    """Convert known legacy comments; refuse to change non-ASCII C code."""
    import re

    try:
        data.decode("utf-8")
        return data
    except UnicodeDecodeError:
        pass
    tokens = re.compile(
        rb'/\*.*?\*/|//[^\r\n]*|"(?:\\[\s\S]|[^"\\])*"|'
        rb"'(?:\\[\s\S]|[^'\\])*'", re.DOTALL,
    )
    code = tokens.sub(
        lambda match: b"" if match[0].startswith((b"/*", b"//")) else match[0],
        data,
    )
    try:
        code.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Non-UTF-8 bytes outside C comments; refusing source conversion") from exc
    return data.decode("iso-8859-1").encode("utf-8")


def ngiflib_preparation():
    """Embed the same guarded converter in both container preparation paths."""
    return (
        'python3 - "$PROJECT_DIR/source/ngiflib.c" <<\'KEA_SOURCE_UTF8_COMMENTS\'\n'
        "from pathlib import Path\nimport sys\n"
        + inspect.getsource(latin1_comments_to_utf8)
        + "\nsource = Path(sys.argv[1])\n"
        "source.write_bytes(latin1_comments_to_utf8(source.read_bytes()))\n"
        "KEA_SOURCE_UTF8_COMMENTS\n"
    )
