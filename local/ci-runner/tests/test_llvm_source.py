"""The image configures apt.llvm.org exactly as tos's install script does.

Jobs run scripts/install-llvm-toolchain.sh, which writes its own keyring and
list file. If the image had configured the same source under another keyring,
apt would refuse every source ("Conflicting values set for option Signed-By")
and the job would fail before installing anything. The expected values come
from the tos script itself; TOS_ROOT is mandatory, so this suite fails rather
than skips without it.
"""

from __future__ import annotations

import base64
import importlib.util
import os
import re
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("build_image_llvm", HERE.parent / "host" / "lib" / "build-image.py")
build_image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build_image)

CODENAME = "noble"
VERSION = "21"


def tos_script_values(text: str) -> tuple[str, str, str]:
    """The keyring, list file and deb line the tos script writes for noble and 21."""
    keyring = re.search(r'^readonly KEYRING="([^"]+)"$', text, re.M)
    assert keyring, "the tos script no longer declares KEYRING"
    write = re.search(r'^echo "(deb [^"]+)" \\\n\s*>(/etc/apt/sources\.list\.d/\S+)$', text, re.M)
    assert write, "the tos script no longer writes its source line this way"
    line = (
        write.group(1)
        .replace("$KEYRING", keyring.group(1))
        .replace("$codename", CODENAME)
        .replace("$version", VERSION)
    )
    assert "$" not in line, line
    return keyring.group(1), write.group(2), line


def image_install_script() -> str:
    """The install script the image build hands to cloud-init, decoded."""
    build_image.GUEST = HERE.parent / "guest"
    data = build_image.user_data(("v0", "https://runner", "0" * 64), ("v0", "https://uv", "0" * 64))
    match = re.search(r"- path: /root/tos-ci-install\n    encoding: b64\n    content: (\S+)", data)
    assert match, "the image has no install script"
    return base64.b64decode(match.group(1)).decode()


class LlvmSourceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = os.environ.get("TOS_ROOT")
        if not root:
            raise AssertionError("TOS_ROOT must name a tos checkout")
        cls.tos = (Path(root) / "scripts" / "install-llvm-toolchain.sh").read_text()

    def test_the_image_uses_the_tos_scripts_keyring_list_and_line(self) -> None:
        keyring, list_file, line = tos_script_values(self.tos)
        self.assertEqual(build_image.LLVM_KEYRING, keyring)
        self.assertEqual(build_image.LLVM_SOURCE_LIST, list_file)
        self.assertEqual(build_image.LLVM_SOURCE_LINE, line)

    def test_the_install_script_writes_only_that_source(self) -> None:
        keyring, list_file, line = tos_script_values(self.tos)
        script = image_install_script()
        self.assertIn(f"gpg --dearmor -o {keyring} /root/llvm.asc\n", script)
        self.assertIn(f"echo '{line}' > {list_file}\n", script)
        # No second configuration of apt.llvm.org under another keyring or file.
        self.assertEqual(script.count("https://apt.llvm.org"), 1, script)
        self.assertEqual(set(re.findall(r"/etc/apt/sources\.list\.d/\S+", script)), {list_file})
        self.assertEqual(set(re.findall(r"/usr/share/keyrings/[^\s\]]+", script)), {keyring})

    def test_the_reviewed_key_check_remains(self) -> None:
        script = image_install_script()
        self.assertIn(build_image.LLVM_KEY_FINGERPRINT, script)
        self.assertIn("grep -c '^pub:'", script)

    def test_a_different_keyring_is_caught(self) -> None:
        keyring, _, _ = tos_script_values(self.tos)
        other = self.tos.replace(f'readonly KEYRING="{keyring}"', 'readonly KEYRING="/usr/share/keyrings/llvm.gpg"')
        self.assertNotEqual(tos_script_values(other)[0], build_image.LLVM_KEYRING)


if __name__ == "__main__":
    unittest.main()
