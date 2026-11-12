# QX DNS 查询逻辑与分流 / 拦截记录持久化 — 差距审计（fix/qx-dns-records）

用户要求（2026-11-11）：「dns 解析的查询逻辑……按 quanx 的来」，分流 / 拦截记录持久化同样对齐 Quantumult X。
本表列出 QX 的行为（带出处）、Tern 改前、改后与代码位置。行号以分支 `fix/qx-dns-records` 为准。

## 出处

- **S** = QX 官方 sample.conf：https://github.com/crossutility/Quantumult-X/blob/master/sample.conf （行号为该文件行号）
- **TF n** = QX TestFlight 更新日志 build n：https://github.com/AssassinOperation/Profile/blob/master/QX_TestFlight_Update.log
- **W** = Lᴜᴄʏ 的 QX 文档：https://wiki.repcz.link/quantumultx/dns/ 、https://wiki.repcz.link/quantumultx/general/

## 差距表

| # | QX 行为（出处） | 改前 | 改后 | 代码 |
|---|---|---|---|---|
| 1 | 多个上游并发查询，最快的结果生效（S:59「the query will be sent to all of the servers simultaneously」；TF 700「并发请求取响应最快的结果」；TF 708「当并发向多个上游 DNS 进行查询时」） | 组内最多 2 台在途，第二台错开 300 ms | 组内全部同时发出（上限 6 台），第一个可用结果生效 | `Shared/NativeCore/NCDNSRace.swift:155`（stagger 0 分支）、`:37` qxParallelCap；`Shared/NativeCore/NCDNSForwarder.swift:223` |
| 2 | 当前网络的 DNS（system）默认一直参与，`no-system` 关闭；doh/doq 存在时 system 与普通服务器被忽略（S:54、S:58） | 导入时写入 `system`，但运行时 `system` 被丢弃（`NCDNSUpstream.parse` 返回 nil），等于从未使用 | `.system` 上游（getaddrinfo，A / AAAA），nameserver 写了 `system` 时加入竞速组；doh/doq 规则沿用导入逻辑 | `Shared/NativeCore/NCDNSQX.swift:195`（NCSystemDNS）、`Shared/NativeCore/NCDNSUpstream.swift:125`（withSystem）、`PacketTunnel/NativeCore/NativeCoreEngine.swift:744`、`Shared/NativeCore/NCDNSForwarder.swift:193` |
| 3 | `server=/example0.com/system` 某域名走系统 DNS（S:85） | nameserver-policy 的 `system` 被丢弃 | `NCDNSUpstream(ref)` 把 `.system` 映射为系统上游 | `Shared/NativeCore/NCDNSUpstream.swift:116` |
| 4 | `circumvent-ipv4-answer` / `circumvent-ipv6-answer`：命中则视为失败并等待其他上游；首个结果中至少一条未命中则不等待，有效结果为未命中的全部记录；支持 `?` `*`（S:63–69；TF 708 第 1 条） | 导入时提示「没有对应项，已忽略」 | 导入为 `dns.circumvent-ipv4-answer/-ipv6-answer`；竞速与单服务器路径都做判定（pass / filtered / circumvented） | `Shared/NativeCore/NCDNSQX.swift:132`、`:170`；`Shared/NativeCore/NCDNSRace.swift:124`；`Shared/NativeCore/NCDNSForwarder.swift:151`；`App/Core/NCConfImportPort.swift:938`；`Shared/NativeCore/NCConfig.swift:129` |
| 5 | `no-ipv6`：AAAA 查询直接失败（S:55） | 导入为 `dns.ipv6: false`，但运行时未使用 | 本地回 NOERROR 空应答。注意：运行时构建器总是用「IPv6」设置覆盖 `dns.ipv6`（`App/Core/NCRuntimeBuilder.swift:188`），所以实际效果是「IPv6 关闭时所有 AAAA 都本地返回空」（与 Clash.Meta `dns.ipv6: false` 一致） | `Shared/NativeCore/NCDNSQX.swift:293`、`PacketTunnel/NativeCore/NativeCoreEngine.swift:756`、`Shared/NativeCore/NCConfig.swift:123` |
| 6 | `dns_reject_domain_behavior` 默认 loopback（127.0.0.1 / ::1，TTL 10），可选 no-error-no-answer（含 SOA，TF 694）/ nxdomain / none（S:24、S:45） | 固定 NXDOMAIN；导入时提示「没有对应设置」 | 四种都实现，默认 loopback；导入为 `dns.reject-domain-behavior`；DNS 日志按实际方式标注拦截 | `Shared/NativeCore/NCDNSQX.swift:17`、`:98`；`Shared/NativeCore/NCDNS.swift:214`；`PacketTunnel/NativeCore/NativeCoreEngine.swift:283`；`PacketTunnel/NativeCore/NCDataPlane.swift:1366`；`App/Core/NCConfImportPort.swift:1103` |
| 7 | DNS 缓存过期标识：命中过期结果时先用过期结果连接，同时发起新查询；网络变化时打过期标识而不是清空（TF 643） | 分流匹配缓存 TTL 夹在 60–600 s，过期即重新查询并等待；网络变化时清空 | NCResolveCache：TTL 10 s – 1 h；过期结果立即可用并后台刷新（最多过期 1 小时）；刷新失败保留旧地址；网络变化 markAllExpired；设置项改名「网络变化时让 DNS 缓存过期」 | `Shared/NativeCore/NCDNSQX.swift:314`、`:354`；`PacketTunnel/NativeCore/NativeCoreEngine.swift:970`、`:1036`；`PacketTunnel/NetworkWatcher.swift:146`；`App/Views/MoreView.swift` |
| 8 | 规则匹配阶段触发的 DNS 查询会被标记，失败也能看出来（TF 718、TF 749） | 分流匹配的查询不写 DNS 日志 | 写入 `[DNS] resolve …`，上游列标注「(分流)」/「(分流, 过期缓存)」；失败写「分流匹配阶段：…」 | `PacketTunnel/NativeCore/NativeCoreEngine.swift:1010`；`Shared/NativeCore/NCDNS.swift`（NCDNSLogLine.ruleResolve） |
| 9 | 流量统计可查看最近几次 VPN 连接（TF 741）；每次开启 VPN（手动或自动重连）生成新的脚本记录，旧的保留（TF 506） | 新会话直接截断上一次的记录文件；单文件上限 256 MB；DNS 历史一次读全部 | 新会话把上一次的文件移到 `.1`（`.1` → `.2`），保留最近两次；单文件上限 32 MB；`readAll` 最多最新 1 万条 | `Shared/NativeCore/NCSessionArchive.swift:25`、`:29`、`:32`、`:60` |
| 10 | （Tern 自己的选择，QX 没有对应）扩展被系统终止后自动重连，接着上次的记录与统计 | 重连即清零 | 上一次没走 stopTunnel 且最后心跳在 30 分钟内（非 App 更新）→ 续接：连接 / DNS 记录文件续写（重建索引、丢掉写了一半的末行），统计快照恢复（同一 session id）；快照每 60 s、休眠、断开时存盘 | `PacketTunnel/PacketTunnelProvider.swift:104`、`:369`、`:493`；`Shared/NativeCore/NCSessionArchive.swift:90`；`Shared/NativeCore/NCStatsRecorder.swift:244`、`:314`；`Shared/NativeCore/NCStatsSnapshot.swift`；`PacketTunnel/NativeMitM/Rewrite/NativeRequestLogStore.swift:281` |

## 已知差距 / 未做

- QX 对「普通」（非 doh/doq）服务器是否也全部并发，sample.conf 没有明说；按 TF 708「并发向多个上游」处理为全部并发。
- 系统 DNS 经 getaddrinfo，只能问 A / AAAA，拿不到真实 TTL（固定 60 s）；其他类型交给组内其他服务器。若系统解析器回到隧道自身（返回 Fake-IP 段地址），该应答被丢弃并记一次日志。
- 过期缓存最长使用 1 小时、缓存 512 个名字：QX 资料没有给出上限，这是 Tern 的取值。
- 续接窗口 30 分钟以最后一次心跳为准（心跳每 2 分钟一次，设备长时间休眠后被杀的情况会开新会话）。App 更新导致的重启不续接。
- QX 的 DNS 记录页按 TTL 显示「过期」中划线（TF 643）——Tern 的 DNS 页面不做此展示，本分支未改 UI。
- 记录文件最多保留 3 份 × 3 种（连接 / DNS / 统计快照），单份 ≤ 32 MB。
