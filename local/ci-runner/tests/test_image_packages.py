"""The CI image provides every package tos's workflows install.

The requirement comes from the workflows (image-packages.json, pinned to their
contents), never from the image's own list. Regenerating it from TOS_ROOT is
mandatory: without TOS_ROOT this suite fails rather than skips.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import workflow_packages as wp  # noqa: E402

SPEC = importlib.util.spec_from_file_location("build_image_pkgs", HERE.parent / "host" / "lib" / "build-image.py")
build_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_image)


class ParserTest(unittest.TestCase):
    def parse(self, text: str) -> set[str]:
        return wp.packages_in(text, "fixture.yml")

    def test_both_install_forms_with_sudo_and_flags(self) -> None:
        self.assertEqual(self.parse("run: sudo apt-get install -y -q gperf\n"), {"gperf"})
        self.assertEqual(self.parse("run: sudo apt install --no-install-recommends -y tmux\n"), {"tmux"})
        self.assertEqual(self.parse("run: apt-get -y install libssl-dev\n"), {"libssl-dev"})
        self.assertEqual(self.parse("run: sudo apt-get -o Dpkg::Use-Pty=0 install -y lld\n"), {"lld"})

    def test_a_backslash_continued_command(self) -> None:
        text = "run: |\n  sudo apt-get install -y \\\n    pkg-config \\\n    zlib1g-dev\n"
        self.assertEqual(self.parse(text), {"pkg-config", "zlib1g-dev"})

    def test_a_run_block_with_two_installs_chains_and_redirects(self) -> None:
        text = ("    run: |\n      sudo apt-get update && sudo apt-get install -y ninja-build ccache > /dev/null\n"
                "      sudo apt install -y texinfo 2>&1 | tail -1; echo done\n")
        self.assertEqual(self.parse(text), {"ninja-build", "ccache", "texinfo"})

    def test_versions_are_reduced_to_the_package(self) -> None:
        self.assertEqual(self.parse("run: sudo apt-get install -y cmake=3.28.3-1build7\n"), {"cmake"})

    def test_comments_install_nothing(self) -> None:
        self.assertEqual(self.parse("# sudo apt-get install -y nothing\nrun: echo # apt-get install no\n"), set())

    def workflow(self, text: str) -> set[str]:
        return wp.workflow_packages(text, "fixture.yml")

    def test_a_folded_block_is_joined_as_yaml_defines(self) -> None:
        text = "jobs:\n  a:\n    steps:\n      - run: >\n          sudo apt-get install -y\n          gperf\n          tmux\n"
        self.assertEqual(self.workflow(text), {"gperf", "tmux"})

    def test_a_long_option_with_an_argument_before_install(self) -> None:
        self.assertEqual(self.parse("run: sudo apt-get --option Dpkg::Use-Pty=0 install -y tmux\n"), {"tmux"})
        self.assertEqual(self.parse("run: apt-get --target-release noble install -y lld\n"), {"lld"})

    def test_an_install_outside_the_decoded_strings_is_refused(self) -> None:
        # Written in a mapping key, it is in the file but in no decoded value.
        with self.assertRaises(wp.DynamicPackage) as caught:
            self.workflow("jobs:\n  a:\n    sudo apt-get install -y gperf: x\n")
        self.assertIn("1 install commands in the file, 0 in its decoded strings", str(caught.exception))

    def test_the_pin_names_its_source_commit(self) -> None:
        self.assertRegex(json.loads(wp.PINNED.read_text())["tos_commit"], r"^[0-9a-f]{40}$")

    def test_dynamic_packages_are_rejected(self) -> None:
        for token in ("$PACKAGES", "${{ matrix.pkg }}", "`cat list`", "lib*-dev", "'quoted'", "\"quoted\""):
            with self.subTest(token), self.assertRaises(wp.DynamicPackage) as caught:
                self.parse(f"run: sudo apt-get install -y gperf {token}\n")
            self.assertIn("fixture.yml:1", str(caught.exception))


class ImageCoversWorkflowsTest(unittest.TestCase):
    def image(self) -> set[str]:
        return set(build_image.BASE_PACKAGES) | set(build_image.LLVM_PACKAGES) | set(build_image.WORKFLOW_PACKAGES)

    def test_the_image_installs_every_pinned_package(self) -> None:
        pinned = set(json.loads(wp.PINNED.read_text())["packages"])
        self.assertTrue(pinned, "the pinned list is empty")
        self.assertEqual(pinned - self.image(), set())

    def test_the_workflow_packages_follow_the_llvm_source(self) -> None:
        script = build_image.user_data(("v0", "https://x/r.tgz", "0" * 64), ("v0", "https://x/u.tgz", "0" * 64))
        import base64
        import re
        install = base64.b64decode(re.search(r"path: /root/tos-ci-install\n    encoding: b64\n    content: (\S+)",
                                             script).group(1)).decode()
        source = install.index("llvm-toolchain-noble-21")
        self.assertGreater(install.index("clang-format-21"), source)
        self.assertIn(" ".join(build_image.WORKFLOW_PACKAGES), install)


class PinnedRegenerationTest(unittest.TestCase):
    def test_the_pin_matches_tos_root_workflows(self) -> None:
        root = os.environ.get("TOS_ROOT")
        self.assertTrue(root, "TOS_ROOT is required: set it to a tos checkout at the pinned workflows")
        derived = wp.derive(Path(root))
        pinned = json.loads(wp.PINNED.read_text())
        # The digest and the list are what must match; the commit names the source.
        self.assertEqual(derived, {k: pinned.get(k) for k in derived},
                         "image-packages.json differs from TOS_ROOT's workflows; regenerate with --write")

    def test_a_new_workflow_package_breaks_the_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github" / "workflows").mkdir(parents=True)
            (root / ".github" / "workflows" / "a.yml").write_text("run: sudo apt-get install -y gperf\n")
            before = wp.derive(root)
            (root / ".github" / "workflows" / "b.yml").write_text("run: sudo apt install -y not-in-the-image\n")
            after = wp.derive(root)
            self.assertNotEqual(before, after)
            self.assertIn("not-in-the-image", after["packages"])


if __name__ == "__main__":
    unittest.main()
