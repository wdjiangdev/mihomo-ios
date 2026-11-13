# Tern 待办

更新：2026-10-27。内核为 NativeCore（纯 Swift + lwIP / WireGuard 的少量 C）。已完成的事项见 `CHANGELOG.md`。

## 归档时未完事项（2026-11-13）

> 2026-11-12 维护者宣布放弃维护；2026-11-13 仓库归档。最后发布：Tern 0.20.3 build 575（main `657541bf`）。组织号镜像仓 `astemo666/mihomo-ios` 不在此次归档范围内。

### 1. 百度地图开屏广告未解

- #221 已合入（QX 同款 MitM + HTTPDNS 固定 IP 种子 + DNS 层 REJECT）。2026-11-12 真机诊断（575）证实机制在工作：114 条 HTTPDNS-guard 拦截、会话累计 40796 次、`lc.map.baidu.com` 的 DNS 被 REJECT。
- 但用户同日实测开屏广告仍在。诊断同时显示广告相关端点仍直连通（`ssp-svr.1rtb.com`、`afd.e.shifen.com` 等），广告源头未定；缓存素材的可能未排除。
- 下一步：飞行模式下打开百度地图（有广告 = 缓存素材，与网络规则无关）；若不是缓存，开着地图看 App 内连接记录，抓漏网的请求。

### 2. WireGuard / AmneziaWG 真机验证未做

- 故障只在真实扩展进程内复现；解析链、服务端（arm02 上 wireguard-go 参考客户端握手成功、ping 三发三中）、进程内并发扫（WG 568ms / AWG 571ms）均已证清白；dnsOverTunnel 保险丝缺陷已由 #211 / build 558 修复并加 `[wg]` 诊断行。
- #223 已合入，但其根因（includeAllNetworks 下 endpoint 被钉死在物理接口）是假设、前提未证。2026-11-12 真机诊断（575）显示：4 份配置中一个 WG 节点都没有、一次 WG 拨号都没发生、零 `[wg]` 行；且两次会话 includeAllNetworks 均为 off——#223 的前提在该设备上不成立。
- 下一步：先在配置里加一个 WG 节点（如 zhiheng kit），选中连一次，再导诊断包凭 `[wg]` 行定罪。

### 3. zhiheng 测试服务清理未做（原交接给 zhihenglu 的第 4 步）

- 机器：zhiheng 45.92.159.155，需 root。
- 已删（11-03 执行过）：`tern-juicity`、`tern-restls`、`tern-snell5`。
- 待删：`tern-sing-box`、`tern-xray`、`tern-brook`、`tern-cloak`、`tern-gost`、`tern-kcptun`、`tern-ssr`、`tern-snell4`、`tern-sshd`（监听 24030，kit 的 SSH 节点，与系统 :22 sshd 无关，别碰错）；六节点验通后删 `tern-ocserv`、`tern-masque`、`tern-connectip`、`tern-trusttunnel`、`tern-sudoku`；SS-Obfs 关单后删 `tern-ssrust`。
- 一律保留：WireGuard / AmneziaWG 服务端、`tern-sub`（kit 订阅文件服务）、全部非 kit 服务。
- 做法：停用 + 禁用 + 删 unit，验 inactive 与端口关闭；配置文件先留着（可逆），别一次清到底。

### 4. 未合入的 PR

- #158 nc-selftest-r1（Self-test 遗留：test10 真 bug 等）。
- #154 naive H2/H3 接管。
- 归档后无法再合；如恢复维护，先 rebase 再定夺。

### 5. 用户侧待办（不在仓库里）

- SelfBuild 订阅地址：GitHub 改名 astemo6 → wdjiangdev 后，gist raw 链接用旧用户名直接 404（不跳转）；Tern 里 SelfBuild 订阅拉取连报 HTTP 404、靠 33 个缓存节点撑着。把 App 内订阅地址里的 `astemo6` 改成 `wdjiangdev`。
- 首页出口 IP 查询失败：2026-11-12 诊断显示 exit-ip 查询连败、头部显示「查询失败」，但内核中转 178 成功、0 失败——疑似 App 侧查询路径问题，原因未定。

### 6. 探针成绩（已收尾，仅留档）

- 最终探针 31/40 出值（SS-Obfs 112/168ms、SS-V2ray 112/167ms 均通）；剩余 5 项经 #222 / #223 解决，已随 0.20.3 build 575 发布。超时 9 节点中 Juicity / Restls / Snell5 服务端已删（超时属预期），Hysteria v1 平台定案关闭。

## 发版前

| # | 事项 | 说明 |
|---|---|---|
| 1 | 改名后的签名 | Bundle ID 改为 `com.wdjiangdev.tern`（`.tunnel` / `.widget`），App Group `group.com.wdjiangdev.tern`。仓库里没有签名 secrets 时 CI 照常出未签名 IPA；若配置签名 secrets，证书的描述文件必须覆盖新 ID 和新 App Group（见 `CI.md`）。 |
| 2 | 旧版用户迁移说明 | 新 App 不继承旧版数据，也不能导入旧版备份：发版说明里写清「旧版备份无法导入，请在 Tern 里重新配置，或重新导入订阅 / 配置链接」。 |
| 3 | 真机回归 | 按 `docs/nativecore-device-checklist.md` 跑一遍（内存、热应用、HTTPS 解密、脚本、小组件 / 控制中心开关需要重新添加）。 |

## 代码整理

| # | 事项 | 说明 |
|---|---|---|
| 1 | 内存治理里的空实现 | `RuntimeMemoryControlling` 与 governor 的堆上限 / 回收一半现在是 no-op（`NativeNoopMemoryControl`）；删掉需要同时改写 governor 的单元测试。 |
| 2 | `RWRegex.lenient` | 恒为 true 的开关，和上一条一起折叠。 |
| 3 | 脚本上下文缓存 | JSC 上下文缓存没有条数上限（`docs/nativecore-memory-budget.md`），加 LRU 上限。 |
| 4 | 小项 | `NCSSRHTTPSimple` 只有测试在用；若干 `Array.removeFirst` 队列可换环形缓冲；`NativeMitmRuntime.errors` 未使用。 |
| 5 | 关于页 GPL 文案 | 「与 … 内核许可一致」的措辞在下次改关于页文案时一并更新（5 种语言）。 |

## 约定

- 测试：推 `test/**` 跑 Self-test 与 Checks；iOS 编译用 `ios.yml` 的 `workflow_dispatch` + `build_only`。同一提交不重复派 run。
- 推 `main` 一律带 `[skip ci]`，否则会触发发版。
- 重写 / 脚本兼容必须通用（Surge / Loon / QX / Egern），不针对单个脚本或 URL 打补丁。
- 文案改动 5 种语言（en / ja / ko / ru / zh-Hans，zh-Hant 由 OpenCC s2twp 生成），`scripts/term_audit.py` 保持通过。
- 只展示真实数据；根页面不观察 DashboardModel；重活不上主线程。
