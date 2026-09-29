"""Single-line terminal progress display for long-running pipeline stages."""

from __future__ import annotations

import sys
import threading
import time
from types import TracebackType
from typing import TextIO


class TerminalSpinner:
    """Render a spinner, elapsed time, and replaceable operation text."""

    _FRAMES = ("|", "/", "-", "\\")

    def __init__(self, operation: str, *, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout
        self._operation = operation
        self._started_at = 0.0
        self._frame_index = 0
        self._last_width = 0
        self._operations: list[str] = []
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "TerminalSpinner":
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()

    def start(self) -> None:
        """Start refreshing the status line."""
        if self._thread is not None:
            return
        self._started_at = time.monotonic()
        self._frame_index = 0
        self._stop_event.clear()
        with self._lock:
            self._render_once_locked()
        self._thread = threading.Thread(
            target=self._render_loop,
            name="pipeline-terminal-spinner",
            daemon=True,
        )
        self._thread.start()

    def update(self, operation: str) -> None:
        """Replace the operation description shown after the elapsed time."""
        with self._lock:
            self._operation = operation
            self._operations.append(operation)
            self._render_once_locked()

    def completed_operations(self) -> list[str]:
        """Return the operations reported during this stage."""
        with self._lock:
            return list(self._operations)

    def notice(self, message: str) -> None:
        """Print a persistent message without disrupting the transient status line."""
        with self._lock:
            self._write("\r" + (" " * self._last_width) + "\r")
            self._stream.write(f"{message}\n")
            self._stream.flush()
            self._last_width = 0
            self._render_once_locked()

    def stop(self) -> None:
        """Stop refreshing and clear the transient terminal line."""
        if self._thread is None:
            return
        self._stop_event.set()
        self._thread.join(timeout=1)
        with self._lock:
            self._write("\r" + (" " * self._last_width) + "\r")
            self._last_width = 0
        self._thread = None

    def _render_loop(self) -> None:
        while not self._stop_event.is_set():
            with self._lock:
                self._render_once_locked()
            self._stop_event.wait(0.1)

    def _render_once_locked(self) -> None:
        elapsed = time.monotonic() - self._started_at
        line = (
            f"[{self._FRAMES[self._frame_index % len(self._FRAMES)]}] "
            f"{self._format_elapsed(elapsed)} {self._operation}"
        )
        padding = " " * max(0, self._last_width - len(line))
        self._write(f"\r{line}{padding}")
        self._last_width = len(line)
        self._frame_index += 1

    def _write(self, data: str) -> None:
        transient_write = getattr(self._stream, "write_transient", None)
        if callable(transient_write):
            transient_write(data)
        else:
            self._stream.write(data)
            self._stream.flush()

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        minutes, remaining = divmod(max(0.0, seconds), 60)
        return f"{int(minutes):02d}:{remaining:04.1f}"
