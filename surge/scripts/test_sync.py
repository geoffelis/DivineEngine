import json
from pathlib import Path
import tempfile
import unittest

import sync
from routing import Router, RuleSet


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = 'https://raw.githubusercontent.com/geoffelis/DivineEngine/main/surge/'
        self.sources = [
            {'id': name, 'url': f'https://example.com/{name}.list', 'type': 'RULE-SET'}
            for name in ('one', 'two')
        ]
        self.module = {'name': 'App', 'path': 'rules/upstream/App.list', 'type': 'RULE-SET', 'phase': 'domain', 'inputs': [{'source': s['id'], 'filter': 'domain'} for s in self.sources]}
        self.config = {'base_url': self.base, 'sources': self.sources, 'modules': [self.module]}
        self.save_config()
        path = self.root / self.module['path']
        path.parent.mkdir(parents=True)
        path.write_bytes(b'DOMAIN,old.example\n')
        (self.root / 'Surge.conf').write_text(
            '[General]\n[Proxy]\n[Proxy Group]\nNoAuto = select, DIRECT\n[Rule]\n'
            f"RULE-SET,{self.base}{self.module['path']},DIRECT\nFINAL,NoAuto,dns-failed\n"
        )

    def save_config(self):
        (self.root / 'sources.json').write_text(json.dumps(self.config))

    def snapshot(self):
        return {str(p.relative_to(self.root)): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_failed_download_keeps_all_files(self):
        before = self.snapshot()
        def fetch(source):
            if source['id'] == 'two':
                raise OSError('upstream unavailable')
            return source['id'], b'DOMAIN,new.example\n'
        with self.assertRaises(OSError):
            sync.sync(self.root, fetch)
        self.assertEqual(before, self.snapshot())

    def test_bad_payload_keeps_all_files(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            sync.sync(self.root, lambda s: (s['id'], b'<html>rate limited</html>'))
        self.assertEqual(before, self.snapshot())

    def test_sync_repeatable_and_detects_tampering(self):
        fetch = lambda s: (s['id'], b'# attribution\nDOMAIN,new.example\n')
        sync.sync(self.root, fetch)
        sync.check(self.root)
        before = self.snapshot()
        sync.sync(self.root, fetch)
        self.assertEqual(before, self.snapshot())
        (self.root / self.module['path']).write_text('DOMAIN,changed.example\n')
        with self.assertRaises(ValueError):
            sync.check(self.root)

    def test_merges_and_deduplicates_without_source_comments(self):
        raw = {'one': b'# NAME: author\nDOMAIN,one.example\nDOMAIN,shared.example\n', 'two': b'// source\nDOMAIN,shared.example\nDOMAIN,two.example\n'}
        output = sync.build(self.config, raw)
        self.assertEqual(output[self.module['path']], b'DOMAIN,one.example\nDOMAIN,shared.example\nDOMAIN,two.example\n')

    def test_rejects_external_runtime_url(self):
        path = self.root / 'Surge.conf'
        path.write_text(path.read_text().replace(self.base, 'https://example.com/'))
        with self.assertRaises(ValueError):
            sync.validate_profile(self.root, self.config)

    def test_rule_formats_not_interchangeable(self):
        with self.assertRaises(ValueError):
            sync.validate_content(b'DOMAIN,example.com\n', {'type': 'DOMAIN-SET'})
        with self.assertRaises(ValueError):
            sync.validate_content(b'.example.com\n', {'type': 'RULE-SET'})

    def test_empty_requires_explicit_exception(self):
        with self.assertRaises(ValueError):
            sync.validate_content(b'# empty\n', {'type': 'RULE-SET'})
        self.assertEqual(sync.validate_content(b'# empty\n', {'type': 'RULE-SET', 'allow_empty': True}), 0)

    def test_policy_normalization_is_opt_in(self):
        data = b'# original attribution\nDOMAIN,ads.example,reject\n'
        with self.assertRaises(ValueError):
            sync.validate_content(data, {'type': 'RULE-SET'})
        source = {'type': 'RULE-SET', 'strip_reject_policy': True}
        normalized = sync.normalize(data, source)
        self.assertEqual(sync.validate_content(normalized, source), 1)
        self.assertEqual(sync.normalize(data, {'type': 'RULE-SET'}), data)

    def test_rejects_policy_cycles(self):
        path = self.root / 'Surge.conf'
        path.write_text(path.read_text().replace('NoAuto = select, DIRECT', 'NoAuto = select, Loop\nLoop = select, NoAuto'))
        with self.assertRaises(ValueError):
            sync.validate_profile(self.root, self.config)

    def test_rejects_nested_upstream_paths(self):
        self.module['path'] = 'rules/upstream/nested/App.list'
        self.save_config()
        with self.assertRaises(ValueError):
            sync.manifest(self.root)

    def test_unassigned_ip_rules_fail_instead_of_silently_dropping(self):
        with self.assertRaises(ValueError):
            sync.build(self.config, {'one': b'DOMAIN,one.example\nIP-CIDR,1.1.1.0/24\n', 'two': b'DOMAIN,two.example\n'})

    def test_mixed_source_is_split_without_losing_ip_rules(self):
        self.config['modules'].append({'name': 'AppIP', 'path': 'rules/upstream/AppIP.list', 'type': 'RULE-SET', 'phase': 'ip', 'inputs': [{'source': 'one', 'filter': 'ip'}]})
        output = sync.build(self.config, {'one': b'DOMAIN,one.example\nIP-CIDR,1.1.1.0/24,no-resolve\n', 'two': b'DOMAIN,two.example\n'})
        self.assertEqual(output['rules/upstream/App.list'], b'DOMAIN,one.example\nDOMAIN,two.example\n')
        self.assertEqual(output['rules/upstream/AppIP.list'], b'IP-CIDR,1.1.1.0/24,no-resolve\n')

    def test_ip_cannot_appear_in_domain_stage(self):
        path = self.root / self.module['path']
        path.write_text('IP-CIDR,1.1.1.0/24\n')
        with self.assertRaises(ValueError):
            sync.validate_profile(self.root, self.config)

    def test_only_explicitly_listed_marker_is_dropped(self):
        self.config['drop_rules'] = ['DOMAIN,marker.example']
        output = sync.build(self.config, {'one': b'DOMAIN,marker.example\nDOMAIN,one.example\n', 'two': b'DOMAIN,other-marker.example\n'})
        self.assertEqual(output[self.module['path']], b'DOMAIN,one.example\nDOMAIN,other-marker.example\n')

    def test_failed_routing_case_keeps_old_files(self):
        (self.root / 'routing-cases.json').write_text(json.dumps([{'host': 'new.example', 'policy': 'REJECT'}]))
        before = self.snapshot()
        with self.assertRaises(ValueError):
            sync.sync(self.root, lambda s: (s['id'], b'DOMAIN,new.example\n'))
        self.assertEqual(before, self.snapshot())

    def test_domain_suffix_obeys_label_boundaries(self):
        (self.root / self.module['path']).write_text('DOMAIN-SUFFIX,service.example\n')
        router = Router(self.root, self.config)
        self.assertEqual(router.match({'host': 'api.service.example'})[0], 'DIRECT')
        self.assertEqual(router.match({'host': 'evilservice.example'})[0], 'NoAuto')
        self.assertEqual(router.match({'host': 'service.example.evil.test'})[0], 'NoAuto')

    def test_stale_generated_modules_removed_after_success(self):
        old = self.root / 'rules/upstream/Retired.list'
        old.write_text('DOMAIN,retired.example\n')
        sync.sync(self.root, lambda s: (s['id'], b'DOMAIN,new.example\n'))
        self.assertFalse(old.exists())

    def test_region_cannot_fall_back_to_unfiltered_group(self):
        path = self.root / 'Surge.conf'
        profile = path.read_text().replace('[Rule]', 'AllServer = select, REJECT\nUnited States = select, AllServer, include-other-group=AllServer, policy-regex-filter=US\n[Rule]')
        path.write_text(profile)
        with self.assertRaises(ValueError):
            sync.validate_profile(self.root, self.config)
        path.write_text(profile.replace('United States = select, AllServer,', 'United States = select, REJECT,'))
        sync.validate_profile(self.root, self.config)

    def test_unknown_logical_rules_are_not_silently_ignored(self):
        for rule in ['OR,((DOMAIN,a.example),(DOMAIN,b.example))', 'NOT,((DOMAIN,a.example))']:
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                RuleSet(rule, 'RULE-SET')


if __name__ == '__main__':
    unittest.main()
