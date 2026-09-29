import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from export_local import compose, export, section


TEMPLATE = '''[Proxy Group]
AllServer = select, include-all-proxies=1
US-ISP = select, 🇺🇸DMIT-ISP
[Rule]
FINAL,US-ISP
'''
PERSONAL = '''[General]
loglevel = notify
[Proxy]
🇺🇸DMIT = trojan, example.com, 443, password=synthetic-secret
🇺🇸DMIT-ISP = trojan, example.net, 443, password=synthetic-isp
[Proxy Group]
AllServer = select, policy-path=你的订阅链接
[Rule]
FINAL,DIRECT
[Host]
example.org = 127.0.0.1
'''


class ExportTests(unittest.TestCase):
    def test_preserves_private_sections_and_replaces_routing(self):
        result, subscribed = compose(TEMPLATE, PERSONAL)
        self.assertFalse(subscribed)
        for name in ('General', 'Proxy', 'Host'):
            self.assertEqual(section(result, name), section(PERSONAL, name))
        for name in ('Proxy Group', 'Rule'):
            self.assertEqual(section(result, name), section(TEMPLATE, name))

    def test_preserves_valid_subscription(self):
        url = 'https://example.com/sub?token=synthetic'
        result, subscribed = compose(TEMPLATE, PERSONAL.replace('你的订阅链接', url))
        self.assertTrue(subscribed)
        self.assertIn('policy-path=' + url, section(result, 'Proxy Group'))

    def test_missing_required_node_fails(self):
        with self.assertRaises(ValueError):
            compose(TEMPLATE, PERSONAL.replace('🇺🇸DMIT-ISP =', 'Other ='))

    def test_export_is_private_and_refuses_repo_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / 'repo' / 'surge'
            root.mkdir(parents=True)
            (root / 'Surge.conf').write_text(TEMPLATE)
            source, output = base / 'personal.conf', base / 'output.conf'
            source.write_text(PERSONAL)
            with self.assertRaises(ValueError):
                export(source, root / 'private.conf', root)
            with contextlib.redirect_stdout(io.StringIO()):
                export(source, output, root)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(source.read_text(), PERSONAL)
            before = output.read_bytes()
            with self.assertRaises(ValueError):
                export(source, output, root)
            self.assertEqual(output.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
