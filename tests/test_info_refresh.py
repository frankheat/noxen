import asyncio
import copy
import queue
import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import patch

from textual.widgets import ContentSwitcher, DataTable

from noxen.app import NoxenApp
from tests.test_info_tab import SNAPSHOT, project_args
from tests.ui_test_case import IsolatedAppTestCase


class SnapshotSession:
    def __init__(self, *responses, blocked=False):
        self.responses = iter(responses)
        self.calls = 0
        self.ready = True
        self.entered = threading.Event()
        self.release = threading.Event()
        if not blocked:
            self.release.set()

    def is_ready(self):
        return self.ready

    def get_app_info(self):
        self.calls += 1
        self.entered.set()
        if not self.release.wait(5):
            raise TimeoutError("test RPC gate timed out")
        response = next(self.responses, None)
        if isinstance(response, Exception):
            raise response
        return copy.deepcopy(response)

    def cleanup(self):
        self.ready = False


class DeferredUI:
    """Control UI delivery, retaining call_from_thread's blocking semantics."""
    def __init__(self):
        self.pending = queue.Queue()
        self.requests = []

    def __call__(self, callback, *args):
        request = SimpleNamespace(callback=callback, args=args, done=threading.Event())
        self.requests.append(request)
        self.pending.put(request)
        if not request.done.wait(5):
            raise TimeoutError("test UI gate timed out")

    async def take(self):
        async with asyncio.timeout(5):
            while self.pending.empty():
                await asyncio.sleep(.01)
        return self.pending.get_nowait()

    def publish(self, request):
        try:
            request.callback(*request.args)
        finally:
            request.done.set()

    def release_all(self):
        for request in self.requests:
            request.done.set()


class InfoRefreshTests(IsolatedAppTestCase):
    @asynccontextmanager
    async def rig(self):
        app = NoxenApp(project_args(str(self.settings_path.parent / "info.noxen")))
        self.addCleanup(app.db.close)
        sessions = []
        ui = DeferredUI()
        async with app.run_test(size=(120, 40)) as pilot:
            with patch.object(app, "call_from_thread", side_effect=ui), patch(
                "noxen.app.time", SimpleNamespace(sleep=lambda _: None)
            ):
                try:
                    yield app, pilot, ui, sessions
                finally:
                    app.workers.cancel_group(app, "app_info")
                    for session in sessions:
                        session.release.set()
                    ui.release_all()
                    app.frida_session = None

    def attach(self, app, sessions, *responses, **kwargs):
        session = SnapshotSession(*responses, **kwargs)
        sessions.append(session)
        app.frida_session = session
        app._connection_state = "connected"
        return session

    def assert_empty(self, app):
        self.assertIsNone(app._app_info)
        self.assertFalse(app.query_one("#info_switcher", ContentSwitcher).display)
        self.assertEqual(app.query_one("#info_comp_table", DataTable).row_count, 0)

    def warnings(self, app):
        return [line for line in app._log_entries if "App info not ready yet" in line]

    async def test_current_refresh_retries_then_populates_the_real_view(self):
        async with self.rig() as (app, pilot, ui, sessions):
            session = self.attach(app, sessions, None, RuntimeError("not ready"), {"error": "starting"}, SNAPSHOT)
            worker = app._fetch_app_info_worker()
            ui.publish(await ui.take())
            await worker.wait()
            self.assertEqual(session.calls, 4)
            self.assertEqual(app._app_info, SNAPSHOT)
            self.assertTrue(app.query_one("#info_switcher", ContentSwitcher).display)
            self.assertEqual(app.query_one("#info_comp_table", DataTable).row_count, 3)
            self.assertEqual(self.warnings(app), [])

    async def test_current_failed_refresh_warns_once_and_keeps_previous_snapshot(self):
        async with self.rig() as (app, pilot, ui, sessions):
            app._apply_app_info(SNAPSHOT)
            session = self.attach(app, sessions)
            worker = app._fetch_app_info_worker()
            ui.publish(await ui.take())
            await worker.wait()
            self.assertEqual(session.calls, 8)
            self.assertEqual(len(self.warnings(app)), 1)
            self.assertEqual(app._app_info, SNAPSHOT)

    async def test_absent_or_unready_session_does_not_fetch_or_warn(self):
        async with self.rig() as (app, pilot, ui, sessions):
            await app._fetch_app_info_worker().wait()
            session = self.attach(app, sessions, SNAPSHOT)
            session.ready = False
            await app._fetch_app_info_worker().wait()
            self.assertEqual(session.calls, 0)
            self.assertTrue(ui.pending.empty())
            self.assertEqual(self.warnings(app), [])
            self.assert_empty(app)

    async def test_disconnect_discards_a_snapshot_already_queued_for_the_ui(self):
        async with self.rig() as (app, pilot, ui, sessions):
            self.attach(app, sessions, SNAPSHOT)
            app._fetch_app_info_worker()
            request = await ui.take()
            app._do_disconnect()
            ui.publish(request)
            self.assert_empty(app)
            self.assertEqual(app._connection_state, "disconnected")

    async def test_disconnecting_while_the_rpc_runs_cannot_restore_info(self):
        async with self.rig() as (app, pilot, ui, sessions):
            session = self.attach(app, sessions, SNAPSHOT, blocked=True)
            app._fetch_app_info_worker()
            async with asyncio.timeout(5):
                while not session.entered.is_set():
                    await asyncio.sleep(.01)
            app._do_disconnect()
            session.release.set()
            ui.publish(await ui.take())
            self.assert_empty(app)
            self.assertEqual(session.calls, 1)

    async def test_replaced_session_discards_old_reply_even_without_another_refresh(self):
        async with self.rig() as (app, pilot, ui, sessions):
            self.attach(app, sessions, SNAPSHOT)
            worker = app._fetch_app_info_worker()
            request = await ui.take()
            self.attach(app, sessions, SNAPSHOT)
            ui.publish(request)
            await worker.wait()
            self.assert_empty(app)

    async def test_new_refresh_wins_even_if_old_reply_is_delivered_last_on_same_session(self):
        async with self.rig() as (app, pilot, ui, sessions):
            latest = copy.deepcopy(SNAPSHOT)
            latest["identity"]["label"] = "Latest snapshot"
            self.attach(app, sessions, SNAPSHOT, latest)
            old_worker = app._fetch_app_info_worker()
            old_reply = await ui.take()
            new_worker = app._fetch_app_info_worker()
            new_reply = await ui.take()
            self.assertTrue(old_worker.is_cancelled)
            ui.publish(new_reply)
            await new_worker.wait()
            ui.publish(old_reply)
            self.assertEqual(app._app_info, latest)

    async def test_clearing_info_invalidates_a_reply_even_if_session_is_unchanged(self):
        async with self.rig() as (app, pilot, ui, sessions):
            self.attach(app, sessions, SNAPSHOT)
            worker = app._fetch_app_info_worker()
            request = await ui.take()
            app._clear_info_tab()
            self.assertTrue(worker.is_cancelled)
            ui.publish(request)
            self.assert_empty(app)

    async def test_session_becoming_unready_before_ui_delivery_discards_snapshot(self):
        async with self.rig() as (app, pilot, ui, sessions):
            session = self.attach(app, sessions, SNAPSHOT)
            worker = app._fetch_app_info_worker()
            request = await ui.take()
            session.ready = False
            ui.publish(request)
            await worker.wait()
            self.assert_empty(app)

    async def test_retry_cannot_switch_to_a_replacement_session(self):
        async with self.rig() as (app, pilot, ui, sessions):
            old = self.attach(app, sessions, None, SNAPSHOT)
            sleeping, resume = threading.Event(), threading.Event()

            def backoff(_seconds):
                sleeping.set()
                if not resume.wait(5):
                    raise TimeoutError("test retry gate timed out")

            with patch("noxen.app.time", SimpleNamespace(sleep=backoff)):
                worker = app._fetch_app_info_worker()
                try:
                    async with asyncio.timeout(5):
                        while not sleeping.is_set():
                            await asyncio.sleep(.01)
                    replacement = self.attach(app, sessions, SNAPSHOT)
                finally:
                    resume.set()
                await worker.wait()
            self.assertEqual(old.calls, 1)
            self.assertEqual(replacement.calls, 0)
            self.assertTrue(ui.pending.empty())
            self.assertEqual(self.warnings(app), [])
            self.assert_empty(app)

    async def test_late_warnings_are_discarded_after_disconnect_replacement_or_refresh(self):
        async with self.rig() as (app, pilot, ui, sessions):
            for mode in ("disconnect", "replacement", "refresh"):
                with self.subTest(mode=mode):
                    app._clear_info_tab()
                    session = self.attach(app, sessions)
                    app._fetch_app_info_worker()
                    old_warning = await ui.take()
                    if mode == "disconnect":
                        app._do_disconnect()
                    else:
                        if mode == "replacement":
                            self.attach(app, sessions, SNAPSHOT)
                        else:
                            session.responses = iter([SNAPSHOT])
                        current = app._fetch_app_info_worker()
                        ui.publish(await ui.take())
                        await current.wait()
                    ui.publish(old_warning)
                    self.assertEqual(self.warnings(app), [])
                    if mode == "disconnect":
                        self.assert_empty(app)
                    else:
                        self.assertEqual(app._app_info, SNAPSHOT)
