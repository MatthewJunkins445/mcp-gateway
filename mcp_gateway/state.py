"""Single-writer state and a hash-chained, payload-free audit trail."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from .security import GuardError, canonical, digest


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardError("Duplicate JSON key")
        result[key] = value
    return result


def _invalid_number(value):
    raise GuardError("Invalid JSON number")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                      parse_constant=_invalid_number)


def write_json(path, value):
    path = Path(path)
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=".pending-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def exclusive_state(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".writer.lock").open("a+b") as stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise GuardError("State is in use; stop the gateway before changing approvals") from error
        try:
            yield directory
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


class Audit:
    def __init__(self, path):
        self.path = Path(path)
        self.sequence, self.head = self.verify(self.path)
        self.failed = False

    @staticmethod
    def verify(path, expected_head=None):
        sequence, head = 0, "0" * 64
        if Path(path).exists():
            with Path(path).open(encoding="utf-8") as stream:
                for line in stream:
                    if not line.endswith("\n"):
                        raise GuardError("Audit record is incomplete")
                    record = json.loads(line, object_pairs_hook=_pairs)
                    actual = record.pop("hash")
                    if record["sequence"] != sequence + 1 or record["previous"] != head or digest(record) != actual:
                        raise GuardError("Audit chain verification failed")
                    sequence, head = record["sequence"], actual
        if expected_head is not None and expected_head != head:
            raise GuardError("Audit head differs from the externally saved checkpoint")
        return sequence, head

    def append(self, event, **fields):
        if self.failed:
            raise GuardError("Audit unavailable")
        record = {"sequence": self.sequence + 1, "previous": self.head,
                  "time": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
        next_head = digest(record)
        try:
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(canonical({**record, "hash": next_head}) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            self.failed = True
            raise GuardError("Audit unavailable") from error
        self.sequence += 1
        self.head = next_head
