# Surge

唯一配置入口是 [`Surge.conf`](Surge.conf)。所有远程列表均指向本仓库，`rules/upstream/` 直接平铺应用模块，不含子目录或作者前缀。

## 接入

仓库中的 `Surge.conf` 包含两个 Trojan 占位节点、29 个带图标的策略组和完整分流规则。占位节点不能连接；推荐从个人配置生成仓库外的私有版本：

```bash
python3 surge/scripts/export_local.py \
  --source /Users/geoffyu/Downloads/GeoffSuperPower.surgeconfig.conf \
  --output /Users/geoffyu/Downloads/GeoffSuperPower.DivineEngine.surgeconfig.conf
```

导出保留原配置的真实节点、General、Host、Rewrite、MITM 等设置，用仓库版本替换策略组和规则；原文件不变。有效的 AllServer 订阅也会保留。输出文件仅当前用户可读写，禁止写入仓库或覆盖已有文件。参考配置的订阅是占位文字，实际仅有两个美国节点；其他地区和 Snell 需补充对应节点或有效订阅。

地区策略组使用 `smart`，通过名称筛选 AllServer 中的节点；没有匹配节点的地区无法使用。Automatic 默认选择美国组，Proxy 默认选择 Automatic。仓库模板中的服务器和密码均为占位值，真实凭据只保存在本地导出文件。

将规则和图标发布到 `geoffelis/DivineEngine` 的 `main` 分支后，即可导入生成的本地配置。若只希望更新规则，也可在本地原配置中替换整个 `[Rule]` 节：

```ini
[Rule]
#!include https://raw.githubusercontent.com/geoffelis/DivineEngine/main/surge/Surge.conf
```

只引入远程配置的规则节，本地节点、订阅、策略组、DNS、Host、Rewrite 和 MITM 继续使用原设置。策略名称与原 GeoffSuperPower 配置兼容，不需添加额外 FINAL。具体语法见 [Surge 分离配置文档](https://manual.nssurge.com/profile/format.html)。旧客户端若不支持远程 include，可以复制远程 `[Rule]` 节到本地，列表仍从本仓库更新。

也可通过上述 URL 导入整份模板，保存为可编辑的本地配置，再替换节点占位值。仓库不存放真实节点密码、订阅或 MITM 证书。

所有策略图标保存在 `icons/`，配置只引用本仓库的图标 URL。重复使用的图标共用文件；`icons/sources.json` 记录下载来源和 SHA-256，便于后续核对。图标 URL 的 `?v=` 使用文件 SHA-256 的前 12 位，更新图片时同步修改，以触发客户端重新下载。图标随仓库提交维护，不参与每日规则同步。

若在图标发布前已导入配置，发布后仍可能因客户端缓存而不显示，单纯重载不一定有效；更新图标 URL 的版本参数后重新加载配置。Mac 的策略组图标需要 Surge 6.5.0 或以上版本，见 [官方参数说明](https://manual.nssurge.com/policy-groups/parameters.html)。

Raw URL 需要能被 Surge 无认证读取。发布前新链接不会可用；私有仓库的普通 Raw 链接不能作为公开订阅使用。

## 应用模块

目前由 63 个来源生成 **65 个模块**，另有 7 个个人规则列表。模块只有有效规则行，去除来源说明和标记域名、合并同类来源、删除重复行。同步地址集中记录在 `sources.json`。

| 类别 | 模块举例 | 策略 |
| --- | --- | --- |
| 银行 / 支付 | `rules/Bank.list` | Bank |
| 券商 | `rules/Trade.list` | Trade |
| 网盘 | `rules/PikPak.list` | United States |
| AI | `AI`、`AppleIntelligence`、`Bing` | AI |
| Apple | `AppleNews`、`AppStore`、`AppleTV`、`AppleCDN`、`Apple` | 美国 / 直连 / Apple |
| 社交 | `Telegram`、`Twitter`、`WeChat`、`Facebook`、`Threads`、`Instagram`、`Discord` | 专用组或 Automatic |
| 流媒体 | `Netflix`、`Disney`、`TikTok`、`BiliBili`、`YouTube`、`Spotify`、`Emby` | 专用组；Spotify / Emby 使用 Automatic |
| 地区流媒体 | `StreamingUS`、`StreamingEU`、`StreamingJP`、`StreamingKR`、`StreamingHK`、`StreamingTW` | 对应地区 |
| 开发 / 系统 | `GitHub`、`SubStore`、`Microsoft`、`OneDrive` | Automatic / Microsoft / OneDrive |
| 国内 / 直连 | `China`、`ChinaDNS`、`Direct`、`XiaoHongShu`、`NetEaseMusic`、`Tesla` | Mainland 或 DIRECT |
| 下载 / 通用 | `Download`、`DownloadDomain`、`CDN`、`CDNDomain`、`Global` | 下载 Mainland；CDN / Global 为 Automatic |
| 广告 / 连接控制 | `Unbreak`、`Reject`、`RejectDomain`、`RejectDrop`、`RejectNoDrop` | 直连例外或对应 REJECT 策略 |
| 其他 | `GoogleSearch`、`Speedtest`、`Riot` | YouTube / Speedtest / 美国 |

每个模块对应一个 `.list` 文件。含 IP 的来源会分离为 `NetflixIP.list`、`ChinaIP.list` 等模块，放在配置的 IP 阶段。`DOMAIN-SET` 内容格式与 `RULE-SET` 不同：`AppleCDN`、`RejectDomain`、`DownloadDomain`、`CDNDomain` 是域名集合，其余是规则集合。

## 匹配顺序与已修正问题

1. 局域网字面量 IP、个人直连 / 券商 / 美国出口例外。
2. AppleNews 地区检测、AI 服务及个人代理例外。
3. 误拦截修正、个人拦截、YouTube UDP 降级和广告过滤。
4. 应用专用规则 → 地区流媒体 → Apple / Microsoft → 国内服务。
5. 下载 → 通用 CDN → 其他海外服务。
6. 未命中域名规则后进入 IP 阶段：局域网 → 拦截 → 应用 → 国内 IP。
7. `FINAL,NoAuto,dns-failed`，沿用原配置的 NoAuto 选择。

本次审查修正：

- AI 附件域名 `oaiusercontent.com`、`claudeusercontent.com` 原先落入通用 CDN，现走 AI。
- 补充 Cursor 主站 / API / CDN / 托管计算机、GitHub Copilot、Microsoft Copilot、OpenRouter 子域名；补充 Spotify 及 TikTok 规则。
- AppleNews 与 Apple Intelligence 共享 `gspe1-ssl.ls.apple.com`，统一交给 United States；其他 Apple Intelligence 域名仍走 AI。
- 拆出混合列表中的 IP 条目，避免国内 IP 提前覆盖广告 IP 或应用 IP；现在连已解析 IP / 直接连接 IP 也遵循该顺序。
- AI 的 `openai` 关键词与个人 `apple-relay` 关键词改为明确域名后缀，避免匹配无关域名。
- 6 个地区 IP 列表只有来源标记域名，没有实际 IP，已移除；空的 global_plus 已合入 Global，不再单独同步。
- 同一应用合并来源并去重，SubStore 单独负责 vercel.app，移除个人 Proxy 中的重复条目。

部分重叠是有意保留的：AI 优先于 GitHub / Microsoft / CDN，OneDrive 优先于 Microsoft，AppStore 优先于 Apple，应用流媒体优先于地区流媒体，个人 PayPal / PikPak 优先于直连下载。`api.github.com` 沿用 AI 来源的选择，供 Copilot 使用；普通 GitHub 域名走 Automatic。详见 [`routing-cases.json`](routing-cases.json) 的预期结果。

NoAuto 默认 Mainland，未匹配流量默认直连；希望兜底代理时，在 Surge 中将 NoAuto 选为 Automatic。Universal Links 拦截、YouTube UDP 降级和 PikPak 固定美国出口沿用个人偏好。

## 银行与券商

`rules/Bank.list` 和 `rules/Trade.list` 是本仓库手工维护的应用列表，同步上游时不会被覆盖，内容不包含作者注释。两者位于广告、CDN 和国内通用规则之前。Bank 和 Trade 都有独立策略组；Bank 默认选择 United States，也可单独切换为 US-ISP。

- **Bank → Bank**：PayPal（含静态资源、PayPal.Me、Venmo / Braintree 支付接口）、Capital One / 360、Chase、Bank of America（含静态资源）、Wells Fargo、Citi、U.S. Bank、PNC、Truist、Ally、Discover、American Express、SoFi、TD 美国网银。TD 仅收录 `tdbank.com`，不将加拿大的整个 `td.com` 强制分到美国。
- **Trade → Trade**：Schwab、Firstrade、Fidelity、Interactive Brokers（含 IBKR 与 TWS 网关）、Vanguard、E*TRADE、Robinhood、Webull、Merrill、moomoo / 富途、Tiger、tastytrade。
- 原 PayPal 规则已归入 Bank；PikPak 由 `rules/PikPak.list` 单独维护，继续走 United States。

使用明确的域名后缀匹配，覆盖同一域名的登录 / API 子域名，不使用 `bank`、`trade`、`paypal` 等泛关键词，也不把共享云服务的整个域名收进金融规则。银行和券商的同域混合业务按域名所属列表路由，例如 Schwab 的银行服务仍随 Trade；两类策略仍可在 Surge 中分别选择出口。金融列表优先级高于广告规则，同域的遥测请求也会使用相同出口。

域名依据官网及官方连接文档核对，第三方登录或新增加的独立域名可能仍需补充。这里只验证规则匹配与配置语法，不涉及登录账户或测试交易。代表性依据：[Capital One](https://www.capitalone.com/)、[PayPal SDK 域名清单](https://developer.paypal.com/sdk/js/v5/best-practices/)、[PayPal / Braintree 支付接口](https://developer.paypal.com/platforms/checkout/fastlane/getstarted/)、[Bank of America 静态资源](https://secure.bankofamerica.com/spa/widgets/gt-footer-unauth-secure-bofa-widget/1.0.0/index.html)、[TD 美国网银](https://www.td.com/us/en/personal-banking)、[Fidelity](https://www.fidelity.com/)、[Interactive Brokers 网关](https://www.interactivebrokers.com/docs/third-party-integrations/tws-settings/best-practice-configure-tws-ib-gateway/connected-ib-server-location-in-tws)、[Merrill](https://www.merrilledge.com/)。

## 维护与自动更新

| 文件 | 用途 |
| --- | --- |
| `Surge.conf` | 唯一配置，维护顺序与策略映射 |
| `rules/*.list` | 个人补充，手工维护，不被同步覆盖 |
| `rules/upstream/*.list` | 自动生成的应用模块，不直接编辑 |
| `sources.json` | 下载来源、模块组合、域名 / IP 分区及排除规则 |
| `sources.lock.json` | 原始来源哈希、生成模块哈希与条数 |
| `routing-cases.json` | 128 个关键分流的预期结果 |
| `scripts/sync.py` | 下载、构建、校验与清理过期模块 |
| `scripts/routing.py` | 用于回归的有限离线匹配模型 |
| `scripts/export_local.py` | 从个人配置生成仓库外的私有配置 |
| `icons/*.png` | 策略组图标，随仓库发布 |
| `icons/sources.json` | 图标来源与文件哈希 |

在仓库根目录运行（Python 3.10+，无需依赖）：

```bash
python3 surge/scripts/sync.py
python3 surge/scripts/sync.py --check
python3 -m unittest discover -s surge/scripts -p 'test_*.py'
```

同步先下载到内存，剥离注释、按应用及域名 / IP 分区合并并去重。全部来源、引用、策略依赖和路由回归通过后，才替换生成文件并清理过期模块。下载 / 校验失败保留原文件；磁盘写入故障可能中断本地批量更新，可重新运行同步。自动工作流只在整批成功后提交。

每条有效来源规则都必须被某个模块消费，只有 `drop_rules` 明确列出的条目允许移除。来源新增 IP 等未分配规则时会报错，避免更新时悄悄丢失。添加来源需在 `sources.json` 配置来源与模块，在 `Surge.conf` 添加对应应用模块；新模块必须平铺且被配置引用。

[工作流](../.github/workflows/surge-rules.yml) 在北京时间每天 06:23 尝试自动同步，也可在 Actions → Sync Surge rules → Run workflow 手动启动。推送和 PR 会执行离线校验与测试。自动同步仅提交生成列表及索引，无内容变化不提交；使用 `GITHUB_TOKEN`，需要仓库规则允许工作流写入 `main`。定时执行可能延迟。

Surge 的列表更新间隔是 86400 秒，也可手动刷新外部资源。调整配置顺序后需刷新远程配置 / include 资源。上游仍负责原始规则内容维护；客户端只访问本仓库，某个上游失效不会使已发布模块失效。

## 验证范围

离线回归覆盖域名、域名后缀、关键词、通配符、字面量 IPv4/IPv6、指定进程、YouTube UDP 降级及兜底。模型不模拟 DNS 解析、ASN 查询、HTTP User-Agent / URL、TLS SNI、真实代理连通性或区域解锁；它不能代替 Surge。模型遇到未支持的逻辑组合会报错。

本机还使用 `surge-cli --check` 对临时配置进行原生校验（把本仓库 URL 暂时映射到本地列表），不会修改正在使用的 Surge 配置。

AI 补充域名依据 [OpenAI 网络说明](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)、[GitHub Copilot 网络清单](https://docs.github.com/en/copilot/reference/copilot-allowlist-reference) 和 [Cursor 网络说明](https://cursor.com/docs/enterprise/network-configuration)。规则分区语义参考 [Surge RULE-SET 文档](https://manual.nssurge.com/rules/ruleset.html)。
