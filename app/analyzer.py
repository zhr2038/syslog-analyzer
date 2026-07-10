from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Iterable

from .rules_engine import SEVERITY_RANK, highest_severity


GENERAL_ONLY_CATEGORIES = {
    "general_event",
    "auth_success",
    "firewall_allow",
    "dhcp_lease",
    "dns_service",
    "ntp_sync",
    "vpn_up",
    "wifi_client_connected",
    "config_change",
    "router_boot",
    "router_clean_shutdown",
    "router_resource_heartbeat",
    "router_reboot_request",
    "router_crashlog_metadata",
}
DETECTOR_OWNED_CATEGORIES = {
    "kernel_crash",
    "router_kernel_crash",
    "router_broadcom_ipv6_crash",
    "router_unclean_reboot",
    "router_service_watchdog_loop",
    "router_soft_lockup",
}

PROBLEM_TEMPLATES: dict[str, dict[str, object]] = {
    "link_down": {
        "title": "链路断开事件",
        "explanation": "接口或端口出现 down，可能导致该链路业务中断。",
        "causes": ["线缆、光模块或对端端口异常", "对端设备重启或端口被关闭", "速率/双工协商失败"],
        "suggestions": ["检查接口物理状态和对端设备日志", "重新插拔或更换线缆/光模块", "核对两端速率、双工和自动协商", "如是核心链路，先切换备用链路再排查"],
    },
    "port_flapping": {
        "title": "接口抖动事件",
        "explanation": "接口出现 flap 或频繁状态变化迹象。",
        "causes": ["物理链路接触不良", "光模块或端口硬件异常", "对端设备重启或协商不稳定"],
        "suggestions": ["查看同一接口前后是否反复 up/down", "更换线缆或光模块", "检查对端端口错误计数", "必要时临时迁移到备用端口"],
    },
    "reboot": {
        "title": "设备重启事件",
        "explanation": "设备或关键服务出现重启记录。",
        "causes": ["人工或计划重启", "供电、电源或温度异常", "固件/进程异常导致自动重启"],
        "suggestions": ["确认是否为计划维护或人工操作", "检查重启前后 5-10 分钟日志", "查看电源、温度、CPU/内存和固件版本", "如果重启反复出现，导出日志并升级稳定固件或联系厂商"],
    },
    "watchdog": {
        "title": "看门狗异常事件",
        "explanation": "设备出现 watchdog 记录，可能是系统卡死后自动恢复或重启。",
        "causes": ["系统进程卡死", "CPU/内存压力过高", "驱动或固件缺陷", "硬件或供电异常"],
        "suggestions": ["查看 watchdog 前的 CPU、内存、温度和内核日志", "确认是否伴随重启、panic、oom 或服务崩溃", "减少高负载任务并观察是否复现", "持续出现时升级固件或提交厂商分析"],
    },
    "kernel_crash": {
        "title": "内核崩溃事件",
        "explanation": "出现 kernel panic、oops、crash 或严重内核异常。",
        "causes": ["固件或驱动缺陷", "内存/存储/硬件异常", "异常流量或功能触发系统缺陷"],
        "suggestions": ["保存 panic/oops 原文和完整时间窗口日志", "记录设备型号和固件版本", "检查崩溃前是否有配置变更或硬件告警", "尽快升级稳定固件或联系厂商支持"],
    },
    "router_unclean_reboot": {
        "title": "路由器疑似非正常重启",
        "explanation": "新启动前没有采集到正常关机标记，更像内核崩溃、卡死后看门狗复位或突然断电。",
        "causes": ["内核/驱动 panic 导致立即复位", "系统卡死后被硬件看门狗重启", "电源、插座或供电适配器瞬时中断"],
        "suggestions": ["查看本次 BOOT_MARKER 后上报的 CRASHLOG 调用链", "查看重启前最后三条 HEARTBEAT 的内存、连接表、负载和温度", "核对同时间 UPS/插座/光猫是否也掉电", "保留该次时间窗口后再做固件或功能隔离对比"],
    },
    "router_kernel_crash": {
        "title": "路由器持久崩溃记录",
        "explanation": "路由器 mtdoops/crashlog 中保留了内核 panic 或 oops，这是异常重启的直接证据。",
        "causes": ["网络加速、无线或交换驱动缺陷", "固件内核缺陷被特定流量或功能触发", "内存或闪存硬件异常"],
        "suggestions": ["保存 CRASHLOG_BEGIN 到 CRASHLOG_END 之间的调用链", "核对崩溃内核版本与当前固件，避免将旧转储当成新故障", "升级到厂商推荐的稳定固件", "仍复现时将调用链、型号、固件和触发时间提交厂商"],
    },
    "router_broadcom_ipv6_crash": {
        "title": "Broadcom IPv6 网络路径崩溃",
        "explanation": "调用链落在 Broadcom 加速收包和 IPv6 TCP 建连路径，属于固件/驱动级问题的强特征。",
        "causes": ["Broadcom runner/flow cache 收包路径的空指针缺陷", "IPv6 TCP 流量触发固件中的边界条件", "第三方固件与底层闭源驱动版本组合问题"],
        "suggestions": ["优先使用包含最新 ASUS GPL 修复的稳定固件", "若新固件仍出现同一调用链，在维护窗口暂停 IPv6 观察", "仍复现再分别暂停硬件加速、AiProtection/流量分析做单变量对比", "不要同时改多项，每个状态至少观察一个原平均崩溃周期"],
    },
    "router_service_watchdog_loop": {
        "title": "ASUS 远程管理服务重启风暴",
        "explanation": "watchdog 持续执行 stop_aae/start_mastiff，表示 ASUS Router App/AiCloud 相关服务没有稳定运行。",
        "causes": ["ASUS 账号绑定或远程连接状态异常", "aae/mastiff 配置损坏或无法访问云端", "当前固件中的服务稳定性缺陷"],
        "suggestions": ["在管理页面检查 ASUS 账号绑定、远程管理和 AiCloud 状态", "如不使用 ASUS Router App/AiCloud，关闭远程功能后观察重启循环是否停止", "如需保留该功能，重新绑定账号并升级稳定固件", "对比路由器整机崩溃时间，确认服务风暴是否为触发条件"],
    },
    "router_crashlog_storage": {
        "title": "路由器 crashlog 分区读取异常",
        "explanation": "专用崩溃分区出现 NAND 不可纠正错误或 I/O error，下次 panic 可能无法完整落盘。",
        "causes": ["crashlog 分区有坏页或 ECC 数据损坏", "旧固件写入的 mtdoops 数据已损坏", "路由器 NAND 闪存开始老化"],
        "suggestions": ["保持远程 syslog 和 5 分钟资源心跳作为主证据", "不要手工反复读写或擦除 mtd3 crashlog 分区", "备份路由器配置并观察 JFFS/其他 NAND 分区是否也报 ECC/I/O 错误", "如错误扩展到 JFFS 或配置丢失，应考虑硬件送修或替换"],
    },
    "router_conntrack_pressure": {
        "title": "路由器连接跟踪表压力过高",
        "explanation": "conntrack 表接近或达到上限，新连接可能丢弃，严重时会放大固件稳定性问题。",
        "causes": ["P2P/下载或大量短连接", "公网扫描、攻击或内网感染终端", "conntrack 上限偏低或超时配置不合理"],
        "suggestions": ["查看高连接数终端和服务", "限制 P2P/下载并关闭不必要的公网暴露端口", "确认连接数回落后是否仍会崩溃", "只在了解内存代价后调整 conntrack 上限"],
    },
    "wan_down": {
        "title": "WAN 链路断开事件",
        "explanation": "外网 WAN 口出现 down、离线或断开。",
        "causes": ["运营商线路或光猫异常", "WAN 口线缆/光模块问题", "上级设备端口异常"],
        "suggestions": ["检查 WAN 口物理灯和光猫状态", "确认上级设备端口是否正常", "重拨或刷新 DHCP 状态", "保留发生时间联系运营商核查线路"],
    },
    "pppoe_down": {
        "title": "PPPoE 拨号异常",
        "explanation": "PPPoE 出现断开、超时或认证失败。",
        "causes": ["运营商链路异常", "账号密码或绑定状态异常", "WAN 物理链路抖动"],
        "suggestions": ["检查 WAN 口和光猫链路", "核对 PPPoE 账号密码和欠费/绑定状态", "手工重拨并观察错误码", "联系运营商提供断开时间和日志"],
    },
    "dhcp_failed": {
        "title": "DHCP 获取地址异常",
        "explanation": "设备或客户端 DHCP 获取地址失败。",
        "causes": ["DHCP 服务不可达", "地址池不足", "VLAN/中继/防火墙策略异常"],
        "suggestions": ["检查 DHCP 服务器或上游网关状态", "确认地址池剩余容量", "核对 VLAN、DHCP relay 和防火墙策略", "抓包确认 discover/offer/request/ack 是否完整"],
    },
    "dhcp_pool_exhausted": {
        "title": "DHCP 地址池耗尽",
        "explanation": "DHCP 没有可分配地址，客户端可能无法获取 IP。",
        "causes": ["地址池范围太小", "异常终端占用大量租约", "租期过长导致旧租约未释放"],
        "suggestions": ["查看 DHCP 租约表和地址池使用率", "扩大地址池或缩短租期", "清理异常/离线租约", "排查是否有异常客户端大量请求地址"],
    },
    "ntp_failed": {
        "title": "时间同步异常",
        "explanation": "设备无法稳定同步时间，可能影响日志时间、证书校验和认证。",
        "causes": ["NTP 服务器不可达", "UDP 123 被防火墙拦截", "系统时间偏差过大或时区配置错误"],
        "suggestions": ["测试到 NTP 服务器的 UDP 123 连通性", "换用备用时间源", "核对时区和当前系统时间", "确认防火墙没有拦截 NTP 流量"],
    },
    "dns_failed": {
        "title": "DNS 解析失败事件",
        "explanation": "设备出现 DNS 解析失败或上游解析超时。",
        "causes": ["上游 DNS 不可达", "外网链路不稳定", "DNS 配置错误或被防火墙拦截"],
        "suggestions": ["测试 DNS 服务器连通性", "临时切换备用 DNS", "检查 UDP/TCP 53 策略", "结合 WAN/PPPoE 日志判断是否由外网故障引起"],
    },
    "auth_failed": {
        "title": "认证失败事件",
        "explanation": "出现登录、密码、RADIUS/LDAP 或服务认证失败。",
        "causes": ["账号密码错误", "认证服务器不可达或策略变化", "异常来源尝试登录"],
        "suggestions": ["确认失败账号、来源和协议", "核对最近密码或权限变更", "检查认证服务器状态", "对异常来源做限制或封禁"],
    },
    "nas_operation_failed": {
        "title": "NAS 文件操作失败",
        "explanation": "NAS 共享文件操作或 SMB 审计日志出现失败，可能影响文件访问、上传、删除或重命名。",
        "causes": ["账号权限或共享 ACL 不足", "客户端访问的路径不存在或被占用", "磁盘空间、配额或文件系统状态异常"],
        "suggestions": ["核对日志中的用户、来源 IP、共享名和文件路径", "检查共享权限、ACL、只读属性和用户配额", "查看同一时间是否有磁盘空间、卷只读或 SMB 服务告警", "让客户端重新认证或重新挂载共享后再验证"],
    },
    "nas_smb_service": {
        "title": "NAS SMB/共享服务异常",
        "explanation": "SMB/Samba 服务出现拒绝、失败、断开或会话异常，客户端访问共享可能不稳定。",
        "causes": ["客户端账号或 SMB 协议版本不兼容", "共享权限、ACL 或访客访问策略不匹配", "SMB 服务重启、连接数过高或网络不稳定"],
        "suggestions": ["确认客户端、账号、共享名和失败动作", "检查 SMB 服务状态、最大连接数和最近配置变更", "核对 Windows 凭据缓存和 NAS 共享权限", "如果只有单个客户端异常，先清理客户端缓存凭据并重新连接"],
    },
    "nas_login_failed": {
        "title": "NAS 登录或认证失败",
        "explanation": "NAS 管理、SSH 或系统认证连续失败，可能是密码错误、权限变化或异常登录尝试。",
        "causes": ["账号密码错误或账号被锁定", "来源地址不在允许访问范围", "存在暴力破解或异常登录尝试"],
        "suggestions": ["确认失败账号、来源 IP、登录入口和失败次数", "检查账号锁定、二次验证、SSH/管理端口暴露情况", "对异常来源做封禁或仅允许内网/管理网段访问", "确认管理员最近是否修改过密码或权限组"],
    },
    "nas_web_login_failed": {
        "title": "NAS Web/客户端登录失败",
        "explanation": "NAS Web、App 或客户端登录失败，可能是密码错误、二次验证失败、账号锁定或异常来源尝试登录。",
        "causes": ["账号密码或二次验证错误", "账号被锁定、禁用或来源不在允许范围", "公网或异常 IP 正在尝试登录"],
        "suggestions": ["确认失败账号、来源 IP、登录入口和失败次数", "检查是否存在公网异常来源或短时间多次失败", "必要时修改密码、启用二次验证并限制管理入口访问范围", "如果是合法用户，核对账号状态、密码策略和客户端缓存凭据"],
    },
    "nas_config_failed": {
        "title": "NAS 配置或权限变更失败",
        "explanation": "NAS 配置、共享、权限、账号或服务设置变更失败，可能导致预期配置没有生效或只部分生效。",
        "causes": ["操作者权限不足或认证状态异常", "配置参数、共享路径、账号或 ACL 不合法", "相关服务繁忙、依赖异常或配置写入失败"],
        "suggestions": ["确认操作者、来源、变更对象和失败错误码", "在 NAS 管理界面核对该配置是否已生效或部分生效", "检查共享路径、ACL、用户组、配额和服务状态", "必要时回滚最近变更，再按单项配置逐步重试"],
    },
    "nas_transfer_failed": {
        "title": "NAS 传输/同步/备份任务失败",
        "explanation": "NAS 下载、上传、同步或备份任务失败，可能导致文件未完整传输或备份缺口。",
        "causes": ["源端或目标端网络不可达、超时或断开", "路径、账号、令牌或远端权限错误", "目标空间不足、文件被占用或任务配置异常"],
        "suggestions": ["确认任务名称、源路径、目标路径和失败对象", "检查 NAS 与远端服务的网络连通性、DNS 和认证凭据", "检查目标卷空间、配额、文件锁定和写入权限", "手动重试小文件验证，再恢复完整同步/备份任务"],
    },
    "nas_storage_alert": {
        "title": "NAS 存储/磁盘/RAID 告警",
        "explanation": "NAS 存储服务、磁盘、卷、文件系统或 RAID 阵列出现异常，需优先保护数据安全。",
        "causes": ["磁盘掉线、坏道、SMART 异常或链路不稳定", "RAID 降级、重建失败或文件系统错误", "卷空间不足、只读挂载或 I/O 错误"],
        "suggestions": ["先确认重要数据已有备份，避免在异常盘上做高风险写入", "在 NAS 存储管理器查看磁盘 SMART、RAID/存储池和卷状态", "检查是否有降级、重建、只读挂载、I/O error 或坏块记录", "硬盘异常持续时准备替换盘，并按厂商流程完成重建"],
    },
    "nas_ups_alert": {
        "title": "NAS UPS 或供电告警",
        "explanation": "NAS UPS、电池、市电或自动关机链路出现异常，断电时可能影响数据安全。",
        "causes": ["UPS USB 连接不稳定或 NUT 配置不匹配", "市电异常、电池低电量或 UPS 不可达", "自动关机策略配置错误"],
        "suggestions": ["检查 UPS 电源输入、电池状态和 USB 连接", "确认 NAS 能读取 UPS 状态且 NUT/UPS 服务正常", "核对低电量自动关机策略和通知策略", "如频繁告警，换 USB 口/线缆并检查 UPS 兼容性"],
    },
    "nas_container_alert": {
        "title": "NAS Docker/容器异常",
        "explanation": "NAS 上 Docker、containerd 或容器服务出现失败、退出、重启或 unhealthy。",
        "causes": ["镜像拉取失败、端口冲突或启动参数错误", "volume 路径权限、挂载目录或文件不存在", "容器内部程序崩溃、资源不足或健康检查失败"],
        "suggestions": ["查看容器状态、退出码和最近容器日志", "检查 compose 配置、端口占用、环境变量和 volume 权限", "确认镜像可拉取且 NAS 网络/DNS 正常", "修复配置后重启单个容器，避免无差别重启整套服务"],
    },
    "vpn_down": {
        "title": "VPN 隧道异常",
        "explanation": "VPN 出现断开、认证失败或协商失败，跨网访问可能受影响。",
        "causes": ["对端不可达或链路抖动", "密钥/证书/账号配置错误", "NAT 穿越或端口策略异常"],
        "suggestions": ["检查对端公网地址和端口连通性", "核对密钥、证书、账号和时间同步", "检查防火墙/NAT 是否放行 VPN 端口", "查看对端同一时间日志确认协商失败阶段"],
    },
    "firewall_drop": {
        "title": "防火墙拦截流量",
        "explanation": "防火墙丢弃、拒绝或阻断了连接/数据包。",
        "causes": ["安全策略正常拦截", "业务流量被误匹配到拒绝规则", "源地址、目的端口或区域划分不符合策略"],
        "suggestions": ["确认源/目的地址、端口、协议和接口方向", "对照防火墙规则顺序查找命中的拒绝策略", "如是业务误拦，新增精确放行规则并保留审计", "持续高频拦截时排查扫描或异常访问来源"],
    },
    "wifi_client_disconnected": {
        "title": "无线终端断开",
        "explanation": "Wi-Fi 客户端断开、去认证或离开无线网络。",
        "causes": ["信号弱、干扰强或漫游阈值不合适", "终端休眠或主动断开", "加密/兼容性问题导致被 AP 断开"],
        "suggestions": ["查看终端 RSSI、信道利用率和干扰情况", "检查断开 reason code 和同一终端是否频繁重连", "调整信道、功率、漫游阈值或加密兼容模式", "对关键终端固定到更近 AP 验证"],
    },
    "ip_conflict": {
        "title": "IP/ARP 地址冲突",
        "explanation": "网络中疑似存在重复 IP 或 ARP 冲突，可能导致访问不稳定。",
        "causes": ["终端手工配置了 DHCP 地址池内 IP", "静态绑定冲突", "异常设备伪造或抢占地址"],
        "suggestions": ["根据日志中的 MAC/接口定位冲突设备", "核对 DHCP 静态绑定和地址池范围", "清理错误的手工 IP 配置", "必要时在交换机侧做端口隔离或安全绑定"],
    },
    "interface_error": {
        "title": "接口错误计数异常",
        "explanation": "接口出现 CRC、丢包、双工不匹配或载波异常，链路质量可能较差。",
        "causes": ["网线/光纤/光模块质量问题", "两端速率或双工协商不一致", "对端接口故障或端口接触不良"],
        "suggestions": ["查看接口错误计数是否持续增长", "更换线缆或光模块", "核对两端速率、双工和自动协商", "切换端口验证是否为硬件问题"],
    },
    "route_change": {
        "title": "路由或网关变化",
        "explanation": "路由表、默认网关或转发路径发生变化，可能影响访问路径。",
        "causes": ["动态路由邻居变化", "默认网关不可达", "配置变更或策略路由误匹配"],
        "suggestions": ["查看变更前后的路由表和默认网关", "确认动态路由邻居状态", "检查最近配置变更", "用 traceroute/ping 验证关键业务路径"],
    },
    "service_lifecycle": {
        "title": "服务停止或退出",
        "explanation": "服务进程停止、退出或被终止，相关功能可能受影响。",
        "causes": ["计划重启或人工操作", "依赖服务异常", "配置错误或资源不足导致进程退出"],
        "suggestions": ["确认是否为计划维护或人工操作", "查看退出码和服务前后日志", "检查配置文件、依赖服务、磁盘和内存", "必要时重启服务并观察是否反复退出"],
    },
    "service_failed": {
        "title": "服务或进程失败",
        "explanation": "服务启动失败、崩溃或达到重启限制。",
        "causes": ["配置文件错误", "依赖端口/文件/权限不可用", "资源不足或程序缺陷"],
        "suggestions": ["查看服务状态和退出码", "检查最近配置变更", "确认端口、权限、磁盘和依赖服务正常", "抓取崩溃日志后再重启或回滚"],
    },
    "firmware_update": {
        "title": "固件或镜像更新事件",
        "explanation": "设备出现固件升级、镜像更新或升级失败相关日志。",
        "causes": ["手工或自动升级", "镜像校验失败", "升级过程中网络/存储/供电异常"],
        "suggestions": ["确认升级是否由计划任务触发", "检查当前固件版本和升级结果", "升级失败时不要反复断电重试", "按厂商流程回滚或重新刷写稳定版本"],
    },
    "storage_device": {
        "title": "外接存储或磁盘设备异常",
        "explanation": "USB、磁盘或文件系统出现挂载、断开或 I/O 异常。",
        "causes": ["外接设备供电不稳", "文件系统损坏", "磁盘坏块或连接线问题"],
        "suggestions": ["检查设备是否反复挂载/断开", "查看磁盘 SMART/坏块和文件系统状态", "更换线缆或供电口", "重要数据先备份再修复文件系统"],
    },
    "memory_pressure": {
        "title": "内存不足或 OOM",
        "explanation": "系统内存不足，进程可能被内核终止。",
        "causes": ["进程内存泄漏", "并发或缓存占用过高", "设备内存规格不足"],
        "suggestions": ["查看 OOM 日志中的被杀进程", "检查当前内存和 swap 使用率", "降低异常服务负载或重启泄漏进程", "如持续发生，升级固件或增加资源"],
    },
    "cpu_pressure": {
        "title": "CPU 负载或任务卡顿",
        "explanation": "CPU 负载高、任务卡住或系统响应变慢。",
        "causes": ["异常进程占用 CPU", "中断/软中断过高", "异常流量或驱动问题"],
        "suggestions": ["查看高 CPU 进程和 load average", "检查接口流量、丢包和中断占用", "确认是否有异常扫描或环路", "必要时限流、重启异常服务或升级固件"],
    },
    "hardware_temperature": {
        "title": "温度异常事件",
        "explanation": "设备温度过高或出现散热告警。",
        "causes": ["机柜温度高或通风不良", "灰尘堵塞风道", "设备负载长期偏高"],
        "suggestions": ["检查机房/机柜温度和通风", "清理设备进出风口灰尘", "查看风扇状态和设备负载", "温度持续异常时安排备机或厂商检测"],
    },
    "hardware_fan_power": {
        "title": "风扇或电源异常事件",
        "explanation": "设备风扇、电源模块或供电链路出现异常。",
        "causes": ["风扇故障或转速异常", "电源模块故障", "UPS/插座/电源线不稳定"],
        "suggestions": ["检查风扇转速和电源模块状态灯", "确认 UPS、插座和电源线稳定", "清理灰尘并保证散热空间", "硬件告警持续时准备备件并联系厂商"],
    },
    "connectivity_warning": {
        "title": "网络连通性异常",
        "explanation": "出现超时、不可达或丢包，业务访问可能不稳定。",
        "causes": ["链路抖动或上游网络异常", "路由或防火墙策略问题", "目标服务不可用"],
        "suggestions": ["从设备侧 ping/traceroute 目标地址", "检查 WAN/接口/路由和防火墙日志", "对比同时间其他设备是否也超时", "确认目标服务端口和健康状态"],
    },
    "connection_error": {
        "title": "连接重置或握手异常",
        "explanation": "连接被拒绝、重置或 TLS/证书握手失败。",
        "causes": ["目标服务未监听或主动拒绝", "代理/防火墙中断连接", "证书过期、时间不同步或 TLS 版本不兼容"],
        "suggestions": ["确认目标服务端口正在监听", "检查防火墙、代理和 NAT 路径", "核验证书有效期和系统时间", "用 curl/openssl 从设备侧复现握手错误"],
    },
    "storage_error": {
        "title": "存储空间或文件系统异常",
        "explanation": "磁盘满、文件系统只读或存储写入失败。",
        "causes": ["日志或缓存占满磁盘", "文件系统错误导致只读挂载", "存储设备故障"],
        "suggestions": ["查看磁盘空间和 inode 使用率", "清理过期日志、缓存和临时文件", "检查文件系统错误和设备健康", "恢复写入前先确认数据安全"],
    },
    "generic_error": {
        "title": "未分类错误日志",
        "explanation": "日志包含错误/失败关键词，但未命中特定场景规则。",
        "causes": ["配置、权限、网络或依赖服务异常", "目标资源不存在或状态不满足", "程序内部错误"],
        "suggestions": ["先看进程名、设备名、错误码和失败对象", "向前后各扩大 5-10 分钟日志范围", "检查最近配置变更、权限、连通性和资源状态", "如果同类错误重复出现，用 AI 分析当前筛选日志获得更细根因"],
    },
    "generic_warning": {
        "title": "未分类告警日志",
        "explanation": "日志包含告警、超时或重试关键词，但未命中特定场景规则。",
        "causes": ["临时网络波动", "上游依赖响应慢", "配置兼容性或性能边界问题"],
        "suggestions": ["观察是否连续出现或只是一过性告警", "按设备和时间窗口过滤同类日志", "检查链路质量、服务负载和上游依赖", "如果告警升级为 error，再按错误日志优先处理"],
    },
}


def analyze_entries(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    problems: list[dict[str, object]] = []
    problems.extend(_detect_router_unclean_boot(entries))
    problems.extend(_detect_router_service_watchdog_loops(entries))
    problems.extend(_detect_router_soft_lockups(entries))
    problems.extend(_detect_abnormal_reboot(entries))
    problems.extend(_detect_wan_access_chain(entries))
    problems.extend(_detect_link_flapping(entries))
    problems.extend(_detect_repeated_dns_failures(entries))
    problems.extend(_detect_hardware_environment(entries))
    problems.extend(_detect_auth_failures(entries))
    problems.extend(_detect_kernel_crashes(entries))
    covered_events = _covered_event_keys(problems)
    problems.extend(_detect_uncovered_alerts(entries, covered_events))

    deduped: list[dict[str, object]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for problem in problems:
        signature = (
            str(problem["title"]),
            str(problem["start_time"]),
            str(problem["end_time"]),
            ",".join(problem["devices"]),
        )
        if signature not in seen:
            deduped.append(problem)
            seen.add(signature)

    deduped.sort(
        key=lambda item: (
            SEVERITY_RANK.get(str(item["severity"]), 0),
            str(item.get("end_time") or ""),
        ),
        reverse=True,
    )
    return deduped


def _detect_uncovered_alerts(entries: list[dict[str, object]], covered_events: set[tuple[str, str, str, str]]) -> list[dict[str, object]]:
    alert_entries = [
        entry
        for entry in entries
        if entry.get("severity") in {"critical", "error", "warning"}
        and _event_key(entry) not in covered_events
    ]
    groups = _group_by(alert_entries, lambda item: f"{item.get('device', 'unknown')}|{_primary_problem_category(item)}")
    problems: list[dict[str, object]] = []
    for key, group in groups.items():
        device, category = key.split("|", 1)
        if category in GENERAL_ONLY_CATEGORIES or category in DETECTOR_OWNED_CATEGORIES:
            continue
        template = _template_for_category(category, group)
        problems.append(
            _problem(
                title=str(template["title"]),
                severity=highest_severity([str(item.get("severity") or "info") for item in group], "warning"),
                events=group[-10:],
                explanation=str(template["explanation"]),
                causes=list(template["causes"]),
                suggestions=list(template["suggestions"]),
                devices=[device],
            )
        )
    return problems


def _detect_router_unclean_boot(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    unclean_events = _entries_with_categories(entries, {"router_unclean_reboot"})
    by_device = _group_by(entries, lambda item: str(item["device"]))
    problems: list[dict[str, object]] = []
    root_cause_categories = {
        "kernel_crash",
        "router_kernel_crash",
        "router_broadcom_ipv6_crash",
        "memory_pressure",
        "router_conntrack_pressure",
        "hardware_temperature",
        "hardware_fan_power",
        "router_crashlog_storage",
    }

    for device, device_unclean_events in _group_by(unclean_events, lambda item: str(item["device"])).items():
        boot_event = device_unclean_events[-1]
        related = _events_near(boot_event, by_device.get(device, []), minutes=10, categories=root_cause_categories)
        evidence = [boot_event] + [item for item in related if _event_key(item) != _event_key(boot_event)]
        evidence = evidence[:10]
        categories = _category_set(evidence)

        if "router_broadcom_ipv6_crash" in categories:
            causes = [
                "Broadcom 网络加速/交换驱动在 IPv6 TCP 收包路径上触发空指针",
                "固件底层闭源驱动与当前功能组合存在缺陷",
            ]
        elif categories & {"kernel_crash", "router_kernel_crash"}:
            causes = ["持久 crashlog 已记录内核 panic/oops", "固件或驱动崩溃后路由器立即复位"]
        elif "memory_pressure" in categories:
            causes = ["崩溃前可用内存过低或发生 OOM", "插件、流量分析或服务存在内存泄漏"]
        elif "router_conntrack_pressure" in categories:
            causes = ["连接跟踪表在崩溃前接近耗尽", "P2P、扫描或异常终端造成连接风暴"]
        elif categories & {"hardware_temperature", "hardware_fan_power"}:
            causes = ["崩溃前出现温度或供电告警", "散热或电源瞬时不稳定"]
        else:
            causes = ["系统卡死后被看门狗重启", "突然断电或电源适配器不稳定", "最终 panic 日志未能在复位前发送"]

        problems.append(
            _problem(
                title="路由器疑似非正常重启",
                severity="critical",
                events=evidence,
                explanation="采集器发现上次运行没有留下 CLEAN_SHUTDOWN 就进入新启动，需要按崩溃、看门狗复位或断电处理。",
                causes=causes,
                suggestions=[
                    "优先查看本次启动后上报的 CRASHLOG 调用链",
                    "查看重启前最后三条 HEARTBEAT 的内存、连接表、负载和温度",
                    "核对同时间光猫、NAS 或其他设备是否也掉电",
                    "按证据选择固件升级或单功能隔离对比，不同时改动多项配置",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_router_service_watchdog_loops(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"router_service_watchdog_loop"})
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        window = _first_window(group, minutes=10, threshold=6)
        if not window:
            continue
        problems.append(
            _problem(
                title="ASUS mastiff/aae 服务重启风暴",
                severity="warning",
                events=window[-10:],
                explanation="watchdog 在短时间内反复 stop_aae/start_mastiff，这是 ASUS Router App/AiCloud 远程管理链路的异常循环，不等于整机已重启。",
                causes=[
                    "ASUS 账号绑定或远程连接状态异常",
                    "aae/mastiff 无法访问云端、配置损坏或进程自身退出",
                    "当前固件的远程管理服务缺陷",
                ],
                suggestions=[
                    "在管理页面检查 ASUS 账号绑定、远程管理和 AiCloud 状态",
                    "如不使用 ASUS Router App/AiCloud，关闭远程功能后观察循环是否停止",
                    "如必须使用，先重新绑定账号，再升级或重置该功能配置",
                    "对比整机崩溃时间，确认该风暴是否为触发条件",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_router_soft_lockups(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"router_soft_lockup"})
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        problems.append(
            _problem(
                title="路由器 CPU soft lockup",
                severity="critical",
                events=group[-10:],
                explanation="持久崩溃记录显示一个或多个 CPU 长时间无法调度，内核看门狗已报 soft lockup。",
                causes=[
                    "驱动在中断或内核线程中长时间占用 CPU",
                    "网络加速、加密或流量检测模块死锁",
                    "固件缺陷或极端流量压力触发调度卡死",
                ],
                suggestions=[
                    "保留 soft lockup 中的 CPU 号、被卡住的线程名和调用链",
                    "核对转储内核构建日期，确认是否来自当前固件",
                    "升级稳定固件；复现时根据被卡线程逐项暂停相关加速/安全功能",
                    "同时对比崩溃前心跳，排除高温、内存或 conntrack 耗尽",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_abnormal_reboot(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = [
        entry
        for entry in _entries_with_categories(entries, {"reboot", "watchdog"})
        if "router_soft_lockup" not in entry.get("categories", [])
        and "router_kernel_crash" not in entry.get("categories", [])
    ]
    problems: list[dict[str, object]] = []
    for device, device_events in _group_by(events, lambda item: str(item["device"])).items():
        window = _first_window(device_events, minutes=30, threshold=2)
        if not window:
            continue
        severity = "critical" if _has_category(window, "watchdog") else "error"
        problems.append(
            _problem(
                title="设备疑似异常重启",
                severity=severity,
                events=window,
                explanation="短时间内多次出现 reboot/restart/watchdog 日志，设备可能发生异常重启或自动恢复。",
                causes=[
                    "设备系统卡死后由 watchdog 自动重启",
                    "供电不稳、硬件故障或温度过高",
                    "固件缺陷、内核异常或资源耗尽",
                ],
                suggestions=[
                    "检查设备运行时长、CPU/内存、温度和电源状态",
                    "确认是否有人手工重启或计划任务重启",
                    "导出完整日志并检查重启前 5-10 分钟是否有 panic、oom、thermal 等线索",
                    "如反复出现，建议升级稳定固件或联系厂商排查硬件",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_wan_access_chain(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    problems: list[dict[str, object]] = []
    by_device = _group_by(entries, lambda item: str(item["device"]))
    for device, device_events in by_device.items():
        wan_events = _entries_with_categories(device_events, {"wan_down"})
        access_events = _entries_with_categories(device_events, {"pppoe_down", "dhcp_failed"})
        for wan in wan_events:
            related = _events_after(wan, access_events, minutes=30)
            if related:
                window = [wan] + related[:6]
                problems.append(
                    _problem(
                        title="外网链路或运营商接入异常",
                        severity="error",
                        events=window,
                        explanation="WAN down 后继续出现 PPPoE 断开或 DHCP 获取地址失败，外网接入链路可能不稳定。",
                        causes=[
                            "运营商线路、光猫或上级交换设备异常",
                            "WAN 口网线、光模块、端口协商异常",
                            "PPPoE 账号状态异常或 DHCP 服务不可达",
                        ],
                        suggestions=[
                            "先检查 WAN 口物理状态、光猫状态灯和上级设备端口",
                            "重拨 PPPoE 或释放/更新 DHCP 地址，观察是否恢复",
                            "确认同一时间内是否有大面积运营商故障",
                            "保留发生时间和日志，必要时提交给运营商",
                        ],
                        devices=[device],
                    )
                )
                break
    return problems


def _detect_link_flapping(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"link_down", "link_up", "port_flapping"})
    groups = _group_by(
        events,
        lambda item: f"{item.get('device', 'unknown')}|{item.get('interface') or 'unknown-interface'}",
    )
    problems: list[dict[str, object]] = []
    for key, group in groups.items():
        device, interface = key.split("|", 1)
        direct_flap = _entries_with_categories(group, {"port_flapping"})
        window = direct_flap or _first_window(group, minutes=15, threshold=4)
        if not window:
            continue
        problems.append(
            _problem(
                title=f"链路抖动：{interface}",
                severity="warning",
                events=window,
                explanation="同一接口短时间内反复 link up/down，可能存在物理链路或协商问题。",
                causes=[
                    "网线、光纤、光模块或水晶头接触不良",
                    "端口速率/双工协商不一致",
                    "对端设备重启、端口 flap 或供电异常",
                ],
                suggestions=[
                    "更换网线、光纤或光模块，并检查接口是否松动",
                    "核对两端速率、双工、自动协商和 EEE 节能配置",
                    "查看对端设备同一时间的端口日志",
                    "如接口持续抖动，临时切换备用端口验证",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_repeated_dns_failures(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"dns_failed"})
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        window = _first_window(group, minutes=30, threshold=3)
        if not window:
            continue
        problems.append(
            _problem(
                title="DNS 解析异常",
                severity="warning",
                events=window,
                explanation="短时间内多次 DNS failed，设备可能无法稳定解析域名。",
                causes=[
                    "上游 DNS 服务器不可达或响应慢",
                    "外网链路抖动导致 DNS 请求失败",
                    "设备 DNS 配置错误或被安全策略拦截",
                ],
                suggestions=[
                    "测试设备到 DNS 服务器的连通性和延迟",
                    "临时切换到备用 DNS，例如运营商 DNS 或可信公共 DNS",
                    "检查防火墙是否拦截 UDP/TCP 53",
                    "结合 WAN/PPPoE/DHCP 日志判断是否为外网问题引起",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_hardware_environment(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"hardware_temperature", "hardware_fan_power"})
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        problems.append(
            _problem(
                title="硬件或环境告警",
                severity=highest_severity([str(item["severity"]) for item in group], "warning"),
                events=group[:10],
                explanation="日志中出现温度、风扇或电源相关告警，可能影响设备稳定性。",
                causes=[
                    "机柜温度过高、通风不良或灰尘堵塞",
                    "风扇故障、电源模块异常或供电不稳定",
                    "设备长期高负载导致温度升高",
                ],
                suggestions=[
                    "检查机房温度、设备进出风口和风扇状态",
                    "确认电源模块、插座、UPS 和电源线是否正常",
                    "清理灰尘并保证设备周围散热空间",
                    "硬件告警持续存在时尽快安排备件或厂商检测",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_auth_failures(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(entries, {"auth_failed"})
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        window = _first_window(group, minutes=20, threshold=3)
        if not window:
            continue
        problems.append(
            _problem(
                title="连续认证失败",
                severity="warning",
                events=window,
                explanation="短时间内连续 authentication failed，可能是账号密码错误或异常登录尝试。",
                causes=[
                    "客户端保存了错误密码或账号权限变更",
                    "有人尝试暴力登录设备",
                    "RADIUS/LDAP/本地认证服务异常",
                ],
                suggestions=[
                    "确认失败来源 IP、账号名和登录协议",
                    "核对最近是否改过密码、认证服务器或权限策略",
                    "对异常来源 IP 做限速、封禁或只允许管理网段访问",
                    "检查设备是否开启登录失败告警和审计记录",
                ],
                devices=[device],
            )
        )
    return problems


def _detect_kernel_crashes(entries: list[dict[str, object]]) -> list[dict[str, object]]:
    events = _entries_with_categories(
        entries,
        {"kernel_crash", "router_kernel_crash", "router_broadcom_ipv6_crash"},
    )
    problems: list[dict[str, object]] = []
    for device, group in _group_by(events, lambda item: str(item["device"])).items():
        categories = _category_set(group)
        broadcom_ipv6_path = "router_broadcom_ipv6_crash" in categories
        problems.append(
            _problem(
                title="Broadcom IPv6 网络路径内核崩溃" if broadcom_ipv6_path else "系统内核或固件异常",
                severity="critical",
                events=group[-10:],
                explanation=(
                    "调用链同时出现 bcmsw_rx/bcm_tcp_v4_recv 与 tcp_v6_syn_recv_sock/inet6_sk_rx_dst_set，"
                    "强烈指向 Broadcom 网络加速驱动在 IPv6 TCP 收包路径上的固件缺陷。"
                    if broadcom_ipv6_path
                    else "日志中出现 kernel panic/oops/crash，通常表示系统内核、驱动或固件发生严重异常。"
                ),
                causes=(
                    [
                        "Broadcom runner/flow cache 加速收包路径的空指针缺陷",
                        "IPv6 TCP 建连流量触发闭源驱动的边界条件",
                        "第三方固件与 ASUS 底层 GPL/闭源模块版本组合问题",
                    ]
                    if broadcom_ipv6_path
                    else [
                        "固件 bug、驱动异常或内核模块崩溃",
                        "内存/存储/硬件故障导致系统崩溃",
                        "异常流量或功能触发了设备缺陷",
                    ]
                ),
                suggestions=(
                    [
                        "核对 crashlog 内核版本与当前固件，只对新固件上再次出现的同调用链下结论",
                        "升级到包含最新 ASUS 网络稳定性修复的稳定固件",
                        "若同调用链复现，在维护窗口暂停 IPv6 进行单变量观察",
                        "仍复现再分别暂停硬件加速和流量分析，每次只改一项并保留日志",
                    ]
                    if broadcom_ipv6_path
                    else [
                        "保存完整崩溃日志、固件版本和设备型号",
                        "检查崩溃前是否有配置变更、流量突增或硬件告警",
                        "升级到厂商推荐的稳定固件版本",
                        "如果频繁出现，联系厂商并附带 panic/oops 原文",
                    ]
                ),
                devices=[device],
            )
        )
    return problems


def _problem(
    title: str,
    severity: str,
    events: list[dict[str, object]],
    explanation: str,
    causes: list[str],
    suggestions: list[str],
    devices: list[str] | None = None,
) -> dict[str, object]:
    if not causes:
        causes = ["需要结合原始日志上下文进一步判断"]
    if not suggestions:
        suggestions = ["扩大时间范围查看前后日志", "按设备、关键词和严重级别过滤同类日志", "确认最近是否有配置、链路或上游服务变化"]
    event_times = [item.get("timestamp_dt") for item in events if isinstance(item.get("timestamp_dt"), datetime)]
    start_time = min(event_times).isoformat(sep=" ", timespec="seconds") if event_times else "未知"
    end_time = max(event_times).isoformat(sep=" ", timespec="seconds") if event_times else "未知"
    problem_devices = devices or sorted({str(item.get("device") or "unknown") for item in events})
    return {
        "title": title,
        "severity": severity,
        "start_time": start_time,
        "end_time": end_time,
        "devices": problem_devices,
        "related_logs": [
            {
                "time": str(item.get("time") or ""),
                "device": str(item.get("device") or ""),
                "source_file": str(item.get("source_file") or ""),
                "raw": str(item.get("raw") or ""),
            }
            for item in events[:10]
        ],
        "chinese_explanation": explanation,
        "possible_causes": causes,
        "suggested_steps": suggestions,
    }


def _entries_with_categories(
    entries: Iterable[dict[str, object]],
    categories: set[str],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for entry in entries:
        entry_categories = entry.get("categories")
        if isinstance(entry_categories, list) and any(item in categories for item in entry_categories):
            result.append(entry)
    return result


def _has_category(entries: list[dict[str, object]], category: str) -> bool:
    return any(category in item.get("categories", []) for item in entries)


def _category_set(entries: Iterable[dict[str, object]]) -> set[str]:
    categories: set[str] = set()
    for entry in entries:
        entry_categories = entry.get("categories")
        if isinstance(entry_categories, list):
            categories.update(str(item) for item in entry_categories)
    return categories


def _primary_problem_category(entry: dict[str, object]) -> str:
    entry_categories = entry.get("categories")
    if isinstance(entry_categories, list):
        for category in entry_categories:
            if category in DETECTOR_OWNED_CATEGORIES:
                return str(category)
        for category in entry_categories:
            if category not in GENERAL_ONLY_CATEGORIES and category != "general_event":
                return str(category)
    severity = str(entry.get("severity") or "warning")
    if severity in {"critical", "error"}:
        return "generic_error"
    return "generic_warning"


def _template_for_category(category: str, events: list[dict[str, object]]) -> dict[str, object]:
    if category in PROBLEM_TEMPLATES:
        return PROBLEM_TEMPLATES[category]

    summaries = []
    for event in events:
        summary = str(event.get("chinese_summary") or "").strip()
        if summary and summary not in summaries:
            summaries.append(summary)
    joined = "；".join(summaries[:3]) or "发现未分类异常日志"
    return {
        "title": f"未分类问题：{category}",
        "explanation": joined,
        "causes": ["可能与配置、链路、权限、资源或上游依赖异常有关", "需要结合前后日志和设备状态确认"],
        "suggestions": ["按同一设备和同一时间窗口继续过滤日志", "优先查看错误码、进程名、接口名和失败对象", "检查最近配置变更、链路状态、资源使用率和上游服务状态", "必要时点击 AI 分析当前筛选日志获取更细排障建议"],
    }


def _covered_event_keys(problems: list[dict[str, object]]) -> set[tuple[str, str, str, str]]:
    keys: set[tuple[str, str, str, str]] = set()
    for problem in problems:
        related_logs = problem.get("related_logs")
        if not isinstance(related_logs, list):
            continue
        for item in related_logs:
            if isinstance(item, dict):
                keys.add(
                    (
                        str(item.get("time") or ""),
                        str(item.get("device") or ""),
                        str(item.get("source_file") or ""),
                        str(item.get("raw") or ""),
                    )
                )
    return keys


def _event_key(entry: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(entry.get("time") or ""),
        str(entry.get("device") or ""),
        str(entry.get("source_file") or ""),
        str(entry.get("raw") or ""),
    )


def _group_by(
    entries: Iterable[dict[str, object]],
    key_func,
) -> dict[str, list[dict[str, object]]]:
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for entry in entries:
        groups[str(key_func(entry))].append(entry)
    for group in groups.values():
        group.sort(key=lambda item: (item.get("_timestamp_sort") or "", item.get("_order", 0)))
    return groups


def _first_window(
    entries: list[dict[str, object]],
    minutes: int,
    threshold: int,
) -> list[dict[str, object]] | None:
    timed = [entry for entry in entries if isinstance(entry.get("timestamp_dt"), datetime)]
    if len(timed) >= threshold:
        timed.sort(key=lambda item: item["timestamp_dt"])
        start = 0
        for end, event in enumerate(timed):
            while event["timestamp_dt"] - timed[start]["timestamp_dt"] > timedelta(minutes=minutes):
                start += 1
            if end - start + 1 >= threshold:
                return timed[start : end + 1]

    if len(entries) >= threshold:
        return entries[-threshold:]
    return None


def _events_after(
    start_event: dict[str, object],
    candidates: list[dict[str, object]],
    minutes: int,
) -> list[dict[str, object]]:
    start_dt = start_event.get("timestamp_dt")
    if not isinstance(start_dt, datetime):
        return candidates[:5]

    end_dt = start_dt + timedelta(minutes=minutes)
    return [
        event
        for event in candidates
        if isinstance(event.get("timestamp_dt"), datetime)
        and start_dt <= event["timestamp_dt"] <= end_dt
    ]


def _events_near(
    center_event: dict[str, object],
    candidates: list[dict[str, object]],
    minutes: int,
    categories: set[str],
) -> list[dict[str, object]]:
    center_dt = center_event.get("timestamp_dt")
    matching = _entries_with_categories(candidates, categories)
    if not isinstance(center_dt, datetime):
        return matching[-9:]

    delta = timedelta(minutes=minutes)
    return [
        event
        for event in matching
        if isinstance(event.get("timestamp_dt"), datetime)
        and center_dt - delta <= event["timestamp_dt"] <= center_dt + delta
    ]
