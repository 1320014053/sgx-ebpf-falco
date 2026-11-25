import re
import unittest
from pathlib import Path


class RavenSyscallsTest(unittest.TestCase):
    def test_subscription_matches_translate(self):
        path = Path(__file__).resolve().parents[1] / "trusted" / "raven_syscalls.cpp"
        source = re.sub(r"//[^\n]*|/\*.*?\*/", "", path.read_text(encoding="utf-8"), flags=re.S)
        table = re.search(r"RavenSyscalls::sc_set\(\).*?event_set_to_sc_set\(\{([^}]*)\}", source, re.S)
        translate = re.search(r"RavenSyscalls::translate\([^)]*\)\s*\{(.*?)\n\}", source, re.S)
        self.assertIsNotNone(table, "missing event table in RavenSyscalls::sc_set")
        self.assertIsNotNone(translate, "missing RavenSyscalls::translate definition")
        subscribed = re.findall(r"\bPPME_\w+", table[1])
        handled = re.findall(r"\bcase\s+(PPME_\w+)\s*:", translate[1])
        self.assertTrue(handled, "no PPME cases in RavenSyscalls::translate")
        self.assertCountEqual(subscribed, handled)


if __name__ == "__main__":
    unittest.main()
