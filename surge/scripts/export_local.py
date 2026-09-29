#!/usr/bin/env python3
"""从个人配置生成仓库外的可导入配置；不把节点凭据写入仓库。"""
import argparse
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]


def section_pattern(name):
    return re.compile(r'^\[' + re.escape(name) + r'\][ \t]*\r?\n.*?(?=^\[|\Z)', re.M | re.S)


def section(text, name):
    match = section_pattern(name).search(text)
    if not match:
        raise ValueError(f'配置缺少 [{name}]')
    return match.group(0).rstrip() + '\n\n'


def compose(template, personal):
    proxy = section(personal, 'Proxy')
    names = {line.split('=', 1)[0].strip() for line in proxy.splitlines() if '=' in line and not line.lstrip().startswith(('#', '//', ';'))}
    if not {'🇺🇸DMIT', '🇺🇸DMIT-ISP'} <= names:
        raise ValueError('个人配置缺少模板引用的 DMIT / DMIT-ISP 节点')
    groups = section(template, 'Proxy Group')
    original_groups = section(personal, 'Proxy Group')
    all_server = re.search(r'^AllServer\s*=.*$', original_groups, re.M)
    subscription = None
    if all_server:
        match = re.search(r'(?:^|,)\s*policy-path=([^,\r\n]+)', all_server.group(0))
        if match:
            candidate = match.group(1).strip()
            parsed = urlparse(candidate)
            if parsed.scheme in {'http', 'https'} and parsed.hostname:
                subscription = candidate
    if subscription:
        groups = re.sub(r'^(AllServer\s*=.*)$', lambda m: m.group(1) + ', policy-path=' + subscription, groups, flags=re.M)
    result = section_pattern('Proxy Group').sub(lambda _: groups, personal, count=1)
    result = section_pattern('Rule').sub(lambda _: section(template, 'Rule'), result, count=1)
    if not section_pattern('Rule').search(personal):
        raise ValueError('个人配置缺少 [Rule]')
    return result, bool(subscription)


def export(source, output, root=ROOT):
    source, output = source.resolve(), output.resolve()
    if output.is_relative_to(root.parent.resolve()):
        raise ValueError('含凭据配置必须输出到仓库目录之外')
    if output.exists():
        raise ValueError('输出文件已存在，请使用其他文件名，避免覆盖个人配置')
    result, has_subscription = compose((root / 'Surge.conf').read_text(), source.read_text())
    output.parent.mkdir(parents=True, exist_ok=True)
    # 以仅当前用户可读写的权限输出；不打印任何配置内容。
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(result.encode())
    try:
        os.link(temporary, output)  # 原子创建；如果目标同时被创建则拒绝覆盖。
    finally:
        temporary.unlink(missing_ok=True)
    print(f'已生成本地配置：{output}')
    print('已保留有效订阅。' if has_subscription else '参考文件没有有效订阅 URL；已保留其中的两个本地节点。')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        export(args.source, args.output)
    except (ValueError, OSError) as exc:
        parser.exit(1, f'导出失败：{exc}\n')
