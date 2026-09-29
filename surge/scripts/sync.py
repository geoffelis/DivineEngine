#!/usr/bin/env python3
"""下载来源，按应用合并、去重和分离 IP 规则；仅依赖 Python 3.10+ 标准库。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-WILDCARD',
    'IP-CIDR', 'IP-CIDR6', 'IP-ASN', 'GEOIP', 'PROCESS-NAME', 'PROCESS-PATH',
    'USER-AGENT', 'URL-REGEX', 'AND', 'OR', 'NOT', 'PROTOCOL', 'DEST-PORT',
    'SRC-IP', 'SRC-PORT', 'IN-PORT', 'SUBNET', 'DEVICE-NAME',
}
BUILTINS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'REJECT-NO-DROP', 'REJECT-TINYGIF'}
FILTERED_GROUPS = {'Hong Kong', 'Taiwan', 'Japan', 'Singapore', 'United States', 'United Kingdom', 'Korea', 'Snell'}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def entries(text):
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith(('#', '//', ';')):
            yield re.split(r'\s+(?://|#|;)', line, maxsplit=1)[0].rstrip()


def fields(line):
    return next(csv.reader([line], skipinitialspace=True))


def phase(line):
    return 'ip' if re.search(r'(?:^|[,(])(?:IP-CIDR6?|IP-ASN|GEOIP),', line) else 'domain'


def validate_content(data, source):
    lines = list(entries(data.decode('utf-8-sig')))
    require(lines or source.get('allow_empty', False), '规则集为空')
    for line in lines:
        if source['type'] == 'DOMAIN-SET':
            require(bool(re.fullmatch(r'\.?[a-zA-Z0-9_*-]+(?:\.[a-zA-Z0-9_*-]+)*', line)), '无效 DOMAIN-SET 内容')
        else:
            parts = line.split(',')
            kind = parts[0]
            require(kind in TYPES and len(parts) >= 2, f'未知规则类型：{line[:100]}')
            require(bool(parts[1]), '空规则值')
            if kind not in {'AND', 'OR', 'NOT', 'URL-REGEX'}:
                require(all(p in {'no-resolve', 'extended-matching'} for p in parts[2:]), f'列表包含策略或未知参数：{line[:100]}')
            if kind in {'IP-CIDR', 'IP-CIDR6'}:
                network = ipaddress.ip_network(parts[1], strict=False)
                require(network.version == (6 if kind == 'IP-CIDR6' else 4), 'IP 规则地址族错误')
    return len(lines)


def normalize(data, source):
    if not source.get('strip_reject_policy'):
        return data
    lines = [re.sub(r',reject\s*$', '', line, flags=re.IGNORECASE) for line in entries(data.decode('utf-8-sig'))]
    return ('\n'.join(lines) + '\n').encode()


def valid_module_path(path):
    p = Path(path)
    return len(p.parts) == 3 and p.parts[:2] == ('rules', 'upstream') and bool(re.fullmatch(r'[A-Za-z0-9]+\.list', p.name))


def manifest(root):
    config = json.loads((root / 'sources.json').read_text())
    sources = {}
    urls = set()
    for source in config['sources']:
        require(source['id'] not in sources and source['url'] not in urls, '重复来源')
        require(source['url'].startswith('https://'), '来源必须使用 HTTPS')
        require(source['type'] in {'RULE-SET', 'DOMAIN-SET'}, '未知来源格式')
        sources[source['id']] = source
        urls.add(source['url'])
    paths, used = set(), set()
    for module in config['modules']:
        path = module['path']
        require(valid_module_path(path), '上游列表须按应用命名并平铺，不能嵌套目录')
        require(path not in paths, '重复模块路径')
        require(module['type'] in {'RULE-SET', 'DOMAIN-SET'} and module['phase'] in {'domain', 'ip'}, '无效模块类型')
        require(module['inputs'], '模块缺少来源')
        paths.add(path)
        for item in module['inputs']:
            require(item['source'] in sources, '模块使用未定义来源')
            require(item['filter'] in {'all', 'domain', 'ip'}, '未知筛选条件')
            require(sources[item['source']]['type'] == module['type'], '不能混合 DOMAIN-SET 与 RULE-SET')
            require(item['filter'] == module['phase'] if module['type'] == 'RULE-SET' else item['filter'] == 'all' and module['phase'] == 'domain', '模块分区不一致')
            used.add(item['source'])
    require(used == set(sources), '存在未使用的下载来源')
    return config


def build(config, raw):
    cleaned, used = {}, {}
    dropped = set(config.get('drop_rules', []))
    for source in config['sources']:
        data = normalize(raw[source['id']], source)
        validate_content(data, source)
        cleaned[source['id']] = []
        used[source['id']] = set()
        for line in entries(data.decode('utf-8-sig')):
            if line in dropped or 'DOMAIN,' + line in dropped:
                continue
            if line.startswith(('AND,', 'OR,', 'NOT,')):
                line = re.sub(r'\s+', '', line)
            cleaned[source['id']].append(line)
    output = {}
    for module in config['modules']:
        lines, seen = [], set()
        for item in module['inputs']:
            for line in cleaned[item['source']]:
                if item['filter'] != 'all' and phase(line) != item['filter']:
                    continue
                used[item['source']].add(line)
                if line not in seen:
                    seen.add(line)
                    lines.append(line)
        data = ('\n'.join(lines) + '\n').encode()
        validate_content(data, module)
        output[module['path']] = data
    for sid, lines in cleaned.items():
        missing = set(lines) - used[sid]
        require(not missing, f'{sid} 有未分配到模块的规则（需补充模块或分区）：{sorted(missing)[:3]}')
    return output


def validate_profile(root, config, payloads=None):
    require(list(root.rglob('*.conf')) == [root / 'Surge.conf'] and not list(root.rglob('*.dconf')), '只能有一份 Surge.conf')
    section, sections, rules, policies, groups = '', set(), [], set(BUILTINS), {}
    group_types = {}
    for line in entries((root / 'Surge.conf').read_text()):
        if line.startswith('['):
            require(bool(re.fullmatch(r'\[[A-Za-z ]+\]', line)) and line not in sections, '无效或重复节头')
            section = line
            sections.add(line)
        elif section == '[Rule]':
            rules.append(line)
        elif section in {'[Proxy]', '[Proxy Group]'}:
            name, value = line.split('=', 1)
            name = name.strip()
            require(name not in policies, '重复策略')
            policies.add(name)
            if section == '[Proxy Group]':
                group_types[name] = fields(value.strip())[0]
                groups[name] = fields(value.strip())[1:]
    require({'[General]', '[Proxy]', '[Proxy Group]', '[Rule]'} <= sections, '缺少配置节')
    edges = {}
    for name, members in groups.items():
        for option in members:
            if option.startswith('icon-url='):
                url = option.split('=', 1)[1]
                prefix = config['base_url'] + 'icons/'
                require(url.startswith(prefix), '图标链接必须指向自己的仓库')
                filename, separator, query = url.removeprefix(prefix).partition('?')
                require(bool(re.fullmatch(r'[A-Za-z0-9_-]+\.png', filename)), '无效图标路径')
                data = (root / 'icons' / filename).read_bytes()
                require(data.startswith(b'\x89PNG\r\n\x1a\n'), '图标不是有效 PNG')
                if separator:
                    require(query == 'v=' + digest(data)[:12], '图标版本与文件内容不一致')
        refs = [v for v in members if '=' not in v]
        if name in FILTERED_GROUPS:
            # 显式成员不受 policy-regex-filter 约束，不能用 AllServer 回退。
            if group_types[name] == 'smart':
                require(not refs, f'{name} 的 smart 成员须通过筛选导入，不能添加未筛选成员')
            else:
                require(group_types[name] == 'select' and refs == ['REJECT'], f'{name} 的显式成员必须仅为 REJECT，避免绕过筛选')
            patterns = [v.split('=', 1)[1] for v in members if v.startswith('policy-regex-filter=')]
            require(len(patterns) == 1 and patterns[0], f'{name} 缺少节点筛选条件')
            re.compile(patterns[0])
            require('include-other-group=AllServer' in members, f'{name} 缺少节点来源')
        refs += [v.split('=', 1)[1] for v in members if v.startswith('include-other-group=')]
        require(set(refs) <= policies, f'策略组 {name} 存在未定义成员')
        edges[name] = refs
    def visit(name, chain):
        require(name not in chain, f'策略组循环：{name}')
        for ref in edges.get(name, []):
            visit(ref, chain | {name})
    for name in groups:
        visit(name, set())
    require(rules and rules[-1] == 'FINAL,NoAuto,dns-failed', '缺少最终兜底')
    require(sum(r.startswith('FINAL,') for r in rules) == 1 and len(rules) == len(set(rules)), '重复规则或 FINAL')
    modules = {m['path']: m for m in config['modules']}
    referenced, ip_stage = set(), False
    for line in rules:
        parts = fields(line)
        require(parts[0] in {'RULE-SET', 'DOMAIN-SET', 'FINAL'}, '未知入口类型')
        require((parts[1] if parts[0] == 'FINAL' else parts[2]) in policies, '规则使用未定义策略')
        if parts[0] == 'FINAL':
            continue
        if parts[1] == 'LAN':
            if 'no-resolve' not in parts[3:]:
                ip_stage = True
            continue
        require(parts[1].startswith(config['base_url']), '规则链接必须指向自己的仓库')
        path = parts[1].removeprefix(config['base_url'])
        require('..' not in Path(path).parts and path.startswith('rules/'), '无效规则路径')
        module = modules.get(path, {'type': 'RULE-SET', 'phase': 'domain'})
        require(parts[0] == module['type'], '规则格式不匹配')
        require((module['phase'] == 'ip') == ip_stage, f'域名 / IP 阶段顺序错误：{path}')
        data = payloads[path] if payloads and path in payloads else (root / path).read_bytes()
        validate_content(data, module)
        for rule in entries(data.decode()):
            require(phase(rule) == module['phase'], f'模块含错误分区的规则：{path}')
        require(path not in referenced, '重复引用模块')
        referenced.add(path)
    expected = set(modules) | {str(p.relative_to(root)) for p in (root / 'rules').glob('*.list')}
    require(referenced == expected, '规则引用与模块 / 个人列表不一致')
    return len(rules)


def download(source):
    for attempt in range(3):
        try:
            request = urllib.request.Request(source['url'], headers={'User-Agent': 'DivineEngine-rules-sync/2.0'})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(20 * 1024 * 1024 + 1)
            require(len(data) <= 20 * 1024 * 1024, '规则文件超过 20 MiB')
            validate_content(normalize(data, source), source)
            return source['id'], data
        except Exception as exc:
            if attempt == 2:
                raise ValueError(f"{source['id']}: {exc}") from exc
            time.sleep(attempt + 1)


def atomic_write(path, data):
    if path.exists() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as file:
        temp = Path(file.name)
        file.write(data)
    try:
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)
    return True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sync(root=ROOT, fetch=download):
    config = manifest(root)
    with ThreadPoolExecutor(max_workers=8) as executor:
        raw = dict(executor.map(fetch, config['sources']))
    require(set(raw) == {s['id'] for s in config['sources']}, '下载结果缺失')
    output = build(config, raw)
    validate_profile(root, config, output)
    # 所有下载、生成、结构和路由回归检查均成功后才写文件。
    cases = root / 'routing-cases.json'
    if cases.exists():
        from routing import check_cases
        check_cases(root, config, output)
    lock = {
        'sources': {s['id']: {'url': s['url'], 'sha256': digest(raw[s['id']])} for s in config['sources']},
        'modules': {m['path']: {'sha256': digest(output[m['path']]), 'entries': validate_content(output[m['path']], m)} for m in config['modules']},
    }
    changed = sum(atomic_write(root / path, data) for path, data in output.items())
    for path in (root / 'rules/upstream').glob('*.list'):
        if str(path.relative_to(root)) not in output:
            path.unlink()
    atomic_write(root / 'sources.lock.json', (json.dumps(lock, ensure_ascii=False, indent=2, sort_keys=True) + '\n').encode())
    print(f'同步成功：{len(raw)} 个来源，{len(output)} 个应用模块，{changed} 个文件更新。')


def check(root=ROOT):
    config = manifest(root)
    count = validate_profile(root, config)
    lock = json.loads((root / 'sources.lock.json').read_text())
    require(set(lock['sources']) == {s['id'] for s in config['sources']}, '来源索引不一致')
    require(set(lock['modules']) == {m['path'] for m in config['modules']}, '模块索引不一致')
    for source in config['sources']:
        require(lock['sources'][source['id']]['url'] == source['url'], '来源 URL 与索引不一致')
    for module in config['modules']:
        record = lock['modules'][module['path']]
        data = (root / module['path']).read_bytes()
        require(record['sha256'] == digest(data) and record['entries'] == validate_content(data, module), f"模块哈希或条数不一致：{module['path']}")
        require(len(list(entries(data.decode()))) == len(set(entries(data.decode()))), '模块存在重复行')
    actual = {str(p.relative_to(root)) for p in (root / 'rules/upstream').rglob('*.list')}
    require(actual == set(lock['modules']), '存在未登记或嵌套的模块')
    if (root / 'routing-cases.json').exists():
        from routing import check_cases
        check_cases(root, config)
    print(f'校验通过：1 份配置、{count} 条分流、{len(actual)} 个应用模块。')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='离线校验，不下载或写入')
    args = parser.parse_args()
    try:
        check() if args.check else sync()
    except Exception as exc:
        print(f'失败：{exc}', file=sys.stderr)
        sys.exit(1)
