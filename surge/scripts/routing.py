"""离线回归模型：域名、字面量 IP、进程和协议；不模拟 DNS/ASN/HTTP/SNI。"""
import fnmatch
import ipaddress
import json
import re

from sync import entries, fields, require

LAN = [ipaddress.ip_network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16',
    '224.0.0.0/4', '240.0.0.0/4', '::1/128', 'fc00::/7', 'fe80::/10',
)]


class RuleSet:
    def __init__(self, text, kind):
        self.domains, self.suffixes, self.others = set(), set(), []
        for line in entries(text):
            if kind == 'DOMAIN-SET':
                rule = ('DOMAIN-SUFFIX' if line.startswith('.') else 'DOMAIN', line.lstrip('.'))
            else:
                parts = line.split(',')
                rule = tuple(parts[:2])
            if rule[0] == 'DOMAIN':
                self.domains.add(rule[1].lower())
            elif rule[0] == 'DOMAIN-SUFFIX':
                self.suffixes.add(rule[1].lower())
            elif rule[0] in {'IP-CIDR', 'IP-CIDR6'}:
                self.others.append((rule[0], ipaddress.ip_network(rule[1], strict=False)))
            elif rule[0] in {'AND', 'OR', 'NOT'}:
                require(re.sub(r'\s+', '', line) == 'AND,((PROTOCOL,UDP),(DOMAIN-SUFFIX,googlevideo.com))', '离线模型遇到未支持的逻辑表达式')
                self.others.append(('YOUTUBE-UDP', None))
            else:
                self.others.append(rule)

    def matches(self, context, address):
        host = context.get('host', '').lower().rstrip('.')
        if host in self.domains or (address is None and any('.'.join(host.split('.')[i:]) in self.suffixes for i in range(len(host.split('.'))))):
            return True
        for kind, value in self.others:
            if kind == 'DOMAIN-KEYWORD' and address is None and value in host:
                return True
            if kind == 'DOMAIN-WILDCARD' and address is None and fnmatch.fnmatchcase(host, value):
                return True
            if kind in {'IP-CIDR', 'IP-CIDR6'} and address is not None and address in value:
                return True
            if kind == 'PROCESS-NAME' and context.get('process') == value:
                return True
            if kind == 'YOUTUBE-UDP' and context.get('protocol', 'TCP') == 'UDP' and (host == 'googlevideo.com' or host.endswith('.googlevideo.com')):
                return True
        return False


class Router:
    def __init__(self, root, config, payloads=None):
        self.rules = []
        for line in entries((root / 'Surge.conf').read_text().split('\n[Rule]\n')[1]):
            parts = fields(line)
            if parts[0] == 'FINAL':
                self.rules.append(('FINAL', parts[1], None))
            elif parts[1] == 'LAN':
                self.rules.append(('LAN', parts[2], None))
            else:
                path = parts[1].removeprefix(config['base_url'])
                data = payloads[path] if payloads and path in payloads else (root / path).read_bytes()
                self.rules.append((path, parts[2], RuleSet(data.decode(), parts[0])))

    def match(self, context):
        host = context.get('host', '')
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        for path, policy, ruleset in self.rules:
            if path == 'FINAL':
                return policy, path
            if path == 'LAN':
                if host.lower().endswith('.local') or host.lower() == 'local' or (address is not None and any(address in n for n in LAN)):
                    return policy, path
            elif ruleset.matches(context, address):
                return policy, path
        raise ValueError('没有兜底规则')


def check_cases(root, config, payloads=None):
    cases = json.loads((root / 'routing-cases.json').read_text())
    router = Router(root, config, payloads)
    failures = []
    for case in cases:
        actual, path = router.match(case)
        if actual != case['policy']:
            failures.append(f"{case['host']}: 预期 {case['policy']}，实际 {actual} ({path})")
    require(not failures, '路由回归失败：\n' + '\n'.join(failures))
    print(f'路由回归通过：{len(cases)} 个域名 / IP / 协议场景。')
