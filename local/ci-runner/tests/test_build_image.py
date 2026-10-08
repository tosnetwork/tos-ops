"""Image build: lock acquisition against its deadline, and fail-closed pruning."""

from __future__ import annotations

import fcntl
import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("build_image", HERE.parent / "host" / "lib" / "build-image.py")
build_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_image)


class Clock:
    """A clock that advances only when the code under test sleeps, or by script."""

    def __init__(self, times: list[float] | None = None) -> None:
        self.t = 0.0
        self.times = list(times or [])
        self.sleeps = 0

    def __call__(self) -> float:
        return self.times.pop(0) if self.times else self.t

    def sleep(self, seconds: float) -> None:
        self.sleeps += 1
        self.t += seconds


class LockTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.build, self.maint = str(root / "build.lock"), str(root / "maintenance.lock")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def take(self, deadline: float, clock: Clock):
        return build_image.take_locks(deadline, self.build, self.maint, clock=clock, sleep=clock.sleep)

    def free(self, path: str) -> bool:
        with open(path, "a+") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                return False
            return True

    def hold(self, path: str):
        f = open(path, "a+")
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.addCleanup(f.close)
        return f

    def test_both_locks_within_the_deadline(self) -> None:
        locks = self.take(100, Clock())
        self.assertFalse(self.free(self.build))
        self.assertFalse(self.free(self.maint))
        for f in locks:
            f.close()

    def test_a_passed_deadline_takes_no_lock(self) -> None:
        with self.assertRaisesRegex(SystemExit, "before the deadline"):
            self.take(100, Clock([101]))
        self.assertTrue(self.free(self.build))
        self.assertTrue(self.free(self.maint))

    def test_a_running_build_is_refused(self) -> None:
        self.hold(self.build)
        with self.assertRaisesRegex(SystemExit, "another image build"):
            self.take(100, Clock())
        self.assertTrue(self.free(self.maint))

    def test_a_held_maintenance_lock_times_out_and_releases_the_build_lock(self) -> None:
        self.hold(self.maint)
        clock = Clock()
        with self.assertRaisesRegex(SystemExit, "before the deadline"):
            self.take(30, clock)
        self.assertEqual(clock.sleeps, 7)  # 0, 5, ... 30 tried; 35 is past the deadline
        self.assertTrue(self.free(self.build))

    def test_a_lock_obtained_after_the_deadline_is_given_back(self) -> None:
        # Checked before the attempt (on time), then after acquiring (late).
        with self.assertRaisesRegex(SystemExit, "before the deadline"):
            self.take(100, Clock([0, 0, 101]))
        self.assertTrue(self.free(self.build))
        self.assertTrue(self.free(self.maint))


class PruneTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.images = self.root / "images"
        self.images.mkdir()
        for name in ("gen-1", "gen-2", "gen-3", "gen-4"):
            (self.images / f"{name}.qcow2").write_text("")
            (self.images / f"{name}.qcow2.manifest").write_text("")
        for n in (1, 2):
            (self.root / f"slot{n}").mkdir()
            (self.root / f"slot{n}" / "overlay.qcow2").write_text("")

    def tearDown(self) -> None:
        self.dir.cleanup()

    def left(self) -> list[str]:
        return sorted(p.name for p in self.images.glob("gen-*.qcow2"))

    def test_unreferenced_old_generations_are_removed(self) -> None:
        refs = {"slot1": {"overlay.qcow2", "gen-1.qcow2"}, "slot2": {"overlay.qcow2"}}
        build_image.prune({"gen-3.qcow2", "gen-4.qcow2"}, self.root, self.images,
                          inspect=lambda overlay: refs[overlay.parent.name])
        self.assertEqual(self.left(), ["gen-1.qcow2", "gen-3.qcow2", "gen-4.qcow2"])
        self.assertFalse((self.images / "gen-2.qcow2.manifest").exists())

    def test_one_uninspectable_overlay_prunes_nothing(self) -> None:
        def inspect(overlay: Path) -> set[str]:
            if overlay.parent.name == "slot2":
                raise ValueError("locked")
            return {"overlay.qcow2"}

        with self.assertRaisesRegex(SystemExit, "no generation pruned"):
            build_image.prune({"gen-4.qcow2"}, self.root, self.images, inspect=inspect)
        self.assertEqual(self.left(), ["gen-1.qcow2", "gen-2.qcow2", "gen-3.qcow2", "gen-4.qcow2"])


@unittest.skipUnless(shutil.which("qemu-img"), "qemu-img not installed")
class BackingChainTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)

    def tearDown(self) -> None:
        self.dir.cleanup()

    def test_a_real_chain_names_its_base(self) -> None:
        base, overlay = self.root / "gen-9.qcow2", self.root / "overlay.qcow2"
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", str(base), "1M"], check=True)
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", str(base), str(overlay)],
                       check=True)
        self.assertEqual(build_image.backing_chain(overlay), {"overlay.qcow2", "gen-9.qcow2"})

    def test_a_missing_overlay_is_an_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "qemu-img info failed"):
            build_image.backing_chain(self.root / "absent.qcow2")


if __name__ == "__main__":
    unittest.main()
