"""Hard total provider-call deadline (phase 15K-B, docs/decisiones.md D-097,
the finding after F1): under a Step 6 deadline every real provider call runs
in llm_client.IsolatedCallProvider, a forked child process that is SIGKILLed
and reaped when timeout_seconds - a TOTAL for the whole call - expires.

The bug reproduced here: the SDK timeout is applied by httpx to each network
read, so a server that starts answering and keeps sending bytes (DeepSeek's
keep-alive blank lines on a waiting non-streaming request) keeps one call
alive far past its timeout. The trickle server runs in its own process (the
test process stays single-threaded, like the worker) and reports every
connection's open/close times on CLOCK_MONOTONIC, which is shared by all
processes on Linux. _RawHttpProvider makes the call with http.client, whose
timeout has the same per-operation meaning as the SDKs'; the real SDKs are
exercised against the same server when installed here, and always inside the
worker image (tests/test_backend_worker_supervisor.py).

Run: python -m unittest tests.test_backend_provider_call_deadline
"""
from __future__ import annotations

import http.client
import json
import os
import select
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILL_SCRIPTS_DIR = REPO_ROOT / ".claude" / "skills" / "web3-auditor" / "scripts"
for p in (str(REPO_ROOT), str(SKILL_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import backend.llm_client as llm_client  # noqa: E402
import backend.multi_pass as mp  # noqa: E402
from tests.test_backend_context_selection import _artifact  # noqa: E402
from tests.test_backend_multi_pass import V1, _budget_for, _pass_index, _primary_files, _run, _valid_draft  # noqa: E402

# Answers every request with HTTP headers at once, then one chunk of a blank
# line every INTERVAL seconds for DURATION seconds, then a final "{}" body.
# Prints one JSON line per event: {"port"}, {"open", t}, {"close", t, reason}
# with reason "peer_closed" (the client went away) or "finished".
TRICKLE_SERVER = r'''
import json, select, socket, sys, threading, time
DURATION, INTERVAL = float(sys.argv[1]), float(sys.argv[2])
lock = threading.Lock()
def emit(obj):
    with lock:
        sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
def handle(conn, cid):
    emit({"event": "open", "id": cid, "t": time.monotonic()})
    reason = "finished"
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        while len(body) < length:
            chunk = conn.recv(65536)
            if not chunk:
                break
            body += chunk
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n")
        start = time.monotonic()
        while time.monotonic() - start < DURATION:
            readable, _, _ = select.select([conn], [], [], INTERVAL)
            if readable and not conn.recv(1):
                reason = "peer_closed"
                return
            conn.sendall(b"1\r\n\n\r\n")
        conn.sendall(b"2\r\n{}\r\n0\r\n\r\n")
    except OSError:
        reason = "peer_closed"
    finally:
        emit({"event": "close", "id": cid, "t": time.monotonic(), "reason": reason})
        conn.close()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 0)); srv.listen(64)
emit({"event": "port", "port": srv.getsockname()[1]})
cid = 0
while True:
    conn, _ = srv.accept(); cid += 1
    threading.Thread(target=handle, args=(conn, cid), daemon=True).start()
'''


class _TrickleServer:
    def __init__(self, duration, interval=0.5):
        self.proc = subprocess.Popen([sys.executable, "-c", TRICKLE_SERVER, str(duration), str(interval)], stdout=subprocess.PIPE)
        self.events = []
        self._fd = self.proc.stdout.fileno()
        self._pending = b""
        self.port = self._next_event(10)["port"]

    def _next_event(self, timeout):
        # Raw fd reads: a buffered readline() could hold later lines where
        # select() cannot see them.
        end = time.monotonic() + timeout
        while b"\n" not in self._pending:
            left = end - time.monotonic()
            ready, _, _ = select.select([self._fd], [], [], max(0.0, left))
            if not ready:
                return None
            chunk = os.read(self._fd, 65536)
            if not chunk:
                return None
            self._pending += chunk
        line, self._pending = self._pending.split(b"\n", 1)
        return json.loads(line)

    def collect(self, settle=1.0):
        """Every event reported so far, waiting up to `settle` s for more."""
        while True:
            event = self._next_event(settle)
            if event is None:
                return self.events
            self.events.append(event)

    def connections(self, settle=1.0):
        events = self.collect(settle)
        conns = {}
        for e in events:
            if e["event"] == "open":
                conns[e["id"]] = {"open": e["t"]}
            elif e["event"] == "close":
                conns[e["id"]].update(close=e["t"], reason=e["reason"])
        return [conns[k] for k in sorted(conns)]

    def stop(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()


def _raw_http_call(port, timeout_seconds):
    """One POST whose timeout, like the SDKs', applies to each socket
    operation - never to the whole call."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_seconds)
    try:
        conn.request("POST", "/v1/chat/completions", body=b'{"x":1}', headers={"Content-Type": "application/json"})
        return conn.getresponse().read().decode("utf-8")
    finally:
        conn.close()


class _RawHttpProvider:
    def __init__(self, port):
        self.port = port

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        try:
            return _raw_http_call(self.port, timeout_seconds)
        except OSError as exc:
            raise llm_client.ProviderError("provider call failed: %s" % type(exc).__name__) from exc


class _PassScriptedProvider:
    """Runs inside the isolated child: passes in `slow` (and the FIRST
    attempt of passes in `slow_first`) make a real HTTP call to the trickle
    server; every other call answers at once with a valid draft."""

    def __init__(self, port, slow=(), slow_first=()):
        self.http = _RawHttpProvider(port)
        self.slow = set(slow)
        self.slow_first = set(slow_first)

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        index = _pass_index(prompt)
        retry = "Your previous draft was INVALID" in prompt
        if index in self.slow or (index in self.slow_first and not retry):
            return self.http.complete(prompt, max_output_tokens, timeout_seconds)
        return json.dumps(_valid_draft(_primary_files(prompt)[:1]))


class _AppCalls:
    """Parent side: each complete() is one application attempt."""

    def __init__(self, provider):
        self.provider = provider
        self.spans = []

    def complete(self, prompt, max_output_tokens, timeout_seconds):
        start = time.monotonic()
        try:
            return self.provider.complete(prompt, max_output_tokens, timeout_seconds)
        finally:
            self.spans.append({"start": start, "end": time.monotonic(), "timeout": timeout_seconds,
                               "child": getattr(self.provider, "last_child_pid", None)})


def _child_pids():
    """Live children of this process (Linux /proc)."""
    me = os.getpid()
    out = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                with open("/proc/%s/stat" % entry) as handle:
                    fields = handle.read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if int(fields[1]) == me:
                out.append(int(entry))
    return sorted(out)


def _assert_reaped(test, pid):
    test.assertFalse(os.path.exists("/proc/%d" % pid), "child %d still exists" % pid)
    with test.assertRaises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


@unittest.skipUnless(hasattr(os, "fork") and os.path.isdir("/proc"), "Linux worker only")
class HardCallDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.server = _TrickleServer(duration=8)
        self.addCleanup(self.server.stop)
        self.threads = threading.active_count()

    def test_bug_reproduced_without_isolation_a_3s_timeout_call_lasts_8s(self):
        start = time.monotonic()
        text = _RawHttpProvider(self.server.port).complete("p", 1, 3)
        elapsed = time.monotonic() - start
        self.assertGreaterEqual(elapsed, 7.5)  # the per-read timeout never fired
        self.assertEqual(text, "\n" * 16 + "{}")
        [conn] = self.server.connections()
        self.assertEqual(conn["reason"], "finished")

    def test_isolated_call_is_aborted_at_its_total_deadline(self):
        provider = llm_client.IsolatedCallProvider(_RawHttpProvider(self.server.port))
        start = time.monotonic()
        with self.assertRaises(llm_client.ProviderError) as ctx:
            provider.complete("p", 1, 3)
        elapsed = time.monotonic() - start
        self.assertIn("exceeded its total time limit of 3 s", str(ctx.exception))
        self.assertGreaterEqual(elapsed, 3.0)
        self.assertLess(elapsed, 3.5)
        _assert_reaped(self, provider.last_child_pid)  # killed and reaped before complete() returned
        [conn] = self.server.connections()
        self.assertEqual(conn["reason"], "peer_closed")  # the request itself was aborted, not abandoned
        self.assertLess(conn["close"] - start, 3.6)
        self.assertEqual(_child_pids(), [self.server.proc.pid])
        self.assertEqual(threading.active_count(), self.threads)

    def test_result_error_crash_and_oversize_come_back_controlled(self):
        class Provider:
            def __init__(self, action):
                self.action = action
                self.calls = []

            def complete(self, prompt, max_output_tokens, timeout_seconds):
                self.calls.append({"provider": "x", "timeout": timeout_seconds})
                if self.action == "provider_error":
                    raise llm_client.ProviderError("provider call failed: RateLimitError")
                if self.action == "other":
                    raise KeyError("secret-looking detail")
                if self.action == "crash":
                    os._exit(3)
                if self.action == "print":
                    print("NOISE ON STDOUT")
                return "x" * (llm_client.PROVIDER_CALL_RESULT_MAX_BYTES + 1) if self.action == "huge" else "ok:" + prompt

        inner = Provider("text")
        wrapped = llm_client.IsolatedCallProvider(inner)
        self.assertEqual(wrapped.complete("é", 1, 5), "ok:é")
        self.assertEqual(inner.calls, [{"provider": "x", "timeout": 5}])  # observability records copied back
        cases = {"provider_error": "provider call failed: RateLimitError", "other": "provider call failed: KeyError",
                 "crash": "the isolated call returned no result", "huge": "exceeds"}
        for action, message in cases.items():
            with self.subTest(action=action):
                wrapped = llm_client.IsolatedCallProvider(Provider(action))
                with self.assertRaises(llm_client.ProviderError) as ctx:
                    wrapped.complete("p", 1, 5)
                self.assertIn(message, str(ctx.exception))
                self.assertNotIn("secret-looking", str(ctx.exception))
                _assert_reaped(self, wrapped.last_child_pid)

    def test_pipe_ends_are_closed_in_child_and_parent_on_every_path(self):
        # The child closes the parent's read end inside its guarded path
        # (checked from inside the child), and the parent closes both ends
        # whether the call returns, fails, crashes or times out.
        created = []
        real_pipe = os.pipe

        def recording_pipe():
            ends = real_pipe()
            created.append(ends)
            pipe_inode.append(os.fstat(ends[0]).st_ino)
            return ends

        pipe_inode = []

        class Provider:
            def __init__(self, action):
                self.action = action

            def complete(self, prompt, max_output_tokens, timeout_seconds):
                # By inode, not by number: a closed fd number is reused
                # right away (the child's /dev/null takes the lowest one).
                read_end, write_end = created[-1]
                closed = []
                for fd in (read_end, write_end):
                    try:
                        closed.append(os.fstat(fd).st_ino != pipe_inode[-1])
                    except OSError:
                        closed.append(True)
                if self.action == "error":
                    raise llm_client.ProviderError("provider call failed: %s" % json.dumps(closed))
                if self.action == "crash":
                    os._exit(3)
                if self.action == "hang":
                    time.sleep(30)
                return json.dumps(closed)

        def assert_parent_closed(ends):
            for fd in ends:
                try:
                    self.assertNotEqual(os.fstat(fd).st_ino, pipe_inode[-1])
                except OSError:
                    pass

        with mock.patch.object(llm_client.os, "pipe", recording_pipe):
            self.assertEqual(json.loads(llm_client.IsolatedCallProvider(Provider("ok")).complete("p", 1, 5)), [True, False])
            assert_parent_closed(created[-1])
            with self.assertRaises(llm_client.ProviderError) as ctx:
                llm_client.IsolatedCallProvider(Provider("error")).complete("p", 1, 5)
            self.assertIn("[true, false]", str(ctx.exception))
            assert_parent_closed(created[-1])
            for action, timeout in (("crash", 5), ("hang", 1)):
                with self.subTest(action=action):
                    wrapped = llm_client.IsolatedCallProvider(Provider(action))
                    with self.assertRaises(llm_client.ProviderError):
                        wrapped.complete("p", 1, timeout)
                    assert_parent_closed(created[-1])
                    _assert_reaped(self, wrapped.last_child_pid)

    def test_child_output_never_reaches_the_worker_stdout(self):
        code = (
            "import sys; sys.path[:0] = [%r]; import backend.llm_client as lc\n"
            "class P:\n"
            "    def complete(self, prompt, max_output_tokens, timeout_seconds):\n"
            "        print('NOISE'); sys.stdout.flush(); return 'fine'\n"
            "print(lc.IsolatedCallProvider(P()).complete('p', 1, 5))\n" % str(REPO_ROOT)
        )
        run = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=30)
        self.assertEqual(run.stdout.decode(), "fine\n")

    def test_only_used_under_a_deadline(self):
        inner = _RawHttpProvider(self.server.port)
        self.assertIs(llm_client.provider_for_step6(inner, None), inner)  # single-pass: unchanged
        wrapped = llm_client.provider_for_step6(inner, 285)
        self.assertIsInstance(wrapped, llm_client.IsolatedCallProvider)


@unittest.skipUnless(hasattr(os, "fork") and os.path.isdir("/proc"), "Linux worker only")
class MultiPassHardDeadlineTests(unittest.TestCase):
    """Real time, real processes: the Step 6 minimum-attempt and final
    reserves are patched down so 6 and 8 passes fit a short deadline."""

    def setUp(self):
        self.server = _TrickleServer(duration=60)
        self.addCleanup(self.server.stop)
        self.threads = threading.active_count()
        for name, value in (("STEP6_MIN_ATTEMPT_SECONDS", 1), ("STEP6_FINAL_PIPELINE_RESERVE_SECONDS", 2)):
            patcher = mock.patch.object(llm_client, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _run_passes(self, passes, deadline, per_attempt=llm_client.DEFAULT_PER_ATTEMPT_TIMEOUT_SECONDS, **script):
        # 2 equal files per pass -> exactly `passes` passes.
        art = _artifact([("src/G%02d.sol" % i, 2 * passes - i, 3000) for i in range(2 * passes)])
        app = _AppCalls(llm_client.provider_for_step6(_PassScriptedProvider(self.server.port, **script), deadline))
        start = time.monotonic()
        result, _ = _run(art, _budget_for(art, V1, passes), app, deadline_seconds=deadline, per_attempt_timeout_seconds=per_attempt)
        elapsed = time.monotonic() - start
        self.assertEqual(result["multiPass"]["passCount"], passes)
        return result, app, elapsed

    def _assert_isolation(self, app, conns):
        # every trickle request was aborted by its killed child, one at a
        # time: the next attempt starts only after the previous is gone.
        self.assertTrue(conns)
        self.assertTrue(all(c["reason"] == "peer_closed" for c in conns))
        for before, after in zip(app.spans, app.spans[1:]):
            self.assertLessEqual(before["end"], after["start"])
        for before, after in zip(conns, conns[1:]):
            self.assertLessEqual(before["close"], after["open"])
        for span in app.spans:
            _assert_reaped(self, span["child"])
            self.assertLess(span["end"] - span["start"], span["timeout"] + 0.5)  # hard total per call
        self.assertEqual(_child_pids(), [self.server.proc.pid])
        self.assertEqual(threading.active_count(), self.threads)

    def test_six_passes_timeouts_fail_their_pass_and_the_global_deadline_holds(self):
        deadline = 14
        result, app, elapsed = self._run_passes(6, deadline, slow={2, 5})
        self.assertLessEqual(elapsed, deadline)
        statuses = [p["status"] for p in result["multiPass"]["passes"]]
        self.assertEqual(statuses, [mp.PASS_SUCCESS, mp.PASS_FAILED, mp.PASS_SUCCESS, mp.PASS_SUCCESS, mp.PASS_FAILED, mp.PASS_SUCCESS])
        for failed in (result["multiPass"]["passes"][1], result["multiPass"]["passes"][4]):
            self.assertIn("exceeded its total time limit", failed["failureReason"])
        scope = result["scoredReport"]["scope"]
        self.assertEqual(scope["completeness"], "partial")
        self.assertIn(mp.FAILED_PASSES_REASON_CODE, [r["code"] for r in scope["reasons"]])
        conns = self.server.connections()
        self.assertEqual(len(conns), sum(p["attempts"] for p in result["multiPass"]["passes"] if p["status"] == mp.PASS_FAILED))
        self._assert_isolation(app, conns)

    def test_eight_passes_including_a_timing_out_last_pass(self):
        deadline = 16
        result, app, elapsed = self._run_passes(8, deadline, slow={3, 8})
        self.assertLessEqual(elapsed, deadline)
        passes = result["multiPass"]["passes"]
        self.assertEqual([p["passIndex"] for p in passes if p["status"] == mp.PASS_FAILED], [3, 8])
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "partial")
        self._assert_isolation(app, self.server.connections())

    def test_application_retry_after_an_aborted_call(self):
        # Pass 2's first call is aborted at its total deadline; its second
        # attempt (a new child, started after the first was reaped) succeeds.
        result, app, elapsed = self._run_passes(2, 20, per_attempt=3, slow_first={2})
        self.assertLessEqual(elapsed, 20)
        passes = result["multiPass"]["passes"]
        self.assertEqual([(p["status"], p["attempts"]) for p in passes], [(mp.PASS_SUCCESS, 1), (mp.PASS_SUCCESS, 2)])
        self.assertEqual(result["scoredReport"]["scope"]["completeness"], "complete")
        self.assertEqual(len(app.spans), 3)
        [conn] = self.server.connections()
        self._assert_isolation(app, [conn])


def _sdk_available(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


@unittest.skipUnless(hasattr(os, "fork") and os.path.isdir("/proc"), "Linux worker only")
class RealSdkHardDeadlineTests(unittest.TestCase):
    """The real SDK clients (installed in the worker image; skipped where
    they are not) against the same trickle server, built exactly as the
    worker builds them under a deadline: sdk_max_retries 0 + isolation."""

    def setUp(self):
        self.server = _TrickleServer(duration=8)
        self.addCleanup(self.server.stop)

    def _check(self, provider):
        wrapped = llm_client.provider_for_step6(provider, 285)
        start = time.monotonic()
        with self.assertRaises(llm_client.ProviderError):
            wrapped.complete("p", 1, 3)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 3.5)
        _assert_reaped(self, wrapped.last_child_pid)
        conns = self.server.connections()
        self.assertEqual(len(conns), 1)  # no SDK retry
        self.assertEqual(conns[0]["reason"], "peer_closed")

    @unittest.skipUnless(_sdk_available("openai"), "openai SDK not installed")
    def test_deepseek(self):
        with mock.patch.object(llm_client, "_DEEPSEEK_BASE_URL", "http://127.0.0.1:%d" % self.server.port):
            provider = llm_client.DeepSeekLLMProvider(api_key="fake-not-a-key", model="m", sdk_max_retries=llm_client.sdk_max_retries_for(285))
        self._check(provider)

    @unittest.skipUnless(_sdk_available("anthropic"), "anthropic SDK not installed")
    def test_anthropic(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_BASE_URL": "http://127.0.0.1:%d" % self.server.port}):
            provider = llm_client.AnthropicLLMProvider(api_key="fake-not-a-key", model="m", sdk_max_retries=llm_client.sdk_max_retries_for(285))
        self._check(provider)


if __name__ == "__main__":
    unittest.main()
