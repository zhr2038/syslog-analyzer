# Syslog Analyzer

一个面向家庭/小型机房/NAS 环境的 Docker 化 Syslog 日志分析 Web 程序。

项目使用 **Python 3.11 + FastAPI + Bootstrap + 原生 JavaScript**，读取容器内 `/logs` 下的 syslog-ng 落盘日志，把网络设备、Linux、NAS、SMB 审计、传输任务、存储/UPS/容器等日志翻译成中文，并按规则自动判断问题、给出排障建议。

## 适用场景

- 路由器、交换机、防火墙、AP 等网络设备集中上报 syslog。
- syslog-ng 已经把日志落盘到宿主机目录。
- 希望在浏览器里查看最近日志、搜索关键词、过滤设备和严重级别。
- 希望把英文/原始设备日志翻译成中文。
- 希望自动识别常见问题，例如链路抖动、WAN/PPPoE/DHCP/DNS 异常、异常重启、认证失败、内核崩溃、NAS 存储告警等。
- 希望保留 NAS 审计：谁 SSH 登录、谁执行管理命令、谁改了 NAS 配置、谁访问了哪个共享文件。

## 主要功能

- 日志文件列表：支持 `messages`、`messages-kv.log`、`remote/<设备名>/<日期>.log`。
- 日志明细表：显示时间、设备、级别、中文解释、原始日志。
- 查询过滤：支持最近 `100 / 500 / 1000` 行、关键词、设备名、严重级别。
- 自动分析：输出问题标题、严重级别、时间范围、涉及设备、相关原始日志、中文解释、可能原因、建议处理步骤。
- 规则库：所有识别规则集中在 `rules.yaml`，方便后续维护。
- 可选 AI 分析：启用后可调用 OpenAI 兼容接口，例如 `deepseek-v4-flash`。
- 安全读取：防止路径穿越，只允许读取容器内 `/logs`。
- NAS 自噪声过滤：默认不显示直接引用 `/volume1/docker/syslog*` 相关目录的自维护日志，避免分析器自己的项目目录刷屏。

## 项目结构

```text
.
├── app/
│   ├── __init__.py
│   ├── ai_analyzer.py
│   ├── analyzer.py
│   ├── log_reader.py
│   ├── main.py
│   └── rules_engine.py
├── static/
│   ├── app.js
│   ├── index.html
│   └── styles.css
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── rules.yaml
├── .dockerignore
├── .gitignore
└── README.md
```

## 快速部署

假设 syslog-ng 日志已经在宿主机：

```text
/volume1/docker/syslog/log
```

其中可能包含：

```text
/volume1/docker/syslog/log/messages
/volume1/docker/syslog/log/messages-kv.log
/volume1/docker/syslog/log/remote/<设备名>/<日期>.log
```

克隆项目并启动：

```bash
git clone https://github.com/zhr2038/syslog-analyzer.git
cd syslog-analyzer
docker compose up -d --build
```

访问：

```text
http://<宿主机IP>:8080
```

例如：

```text
http://192.168.1.15:8080
```

健康检查：

```bash
curl http://127.0.0.1:8080/health
```

## Docker Compose

默认 `docker-compose.yml`：

```yaml
services:
  syslog-analyzer:
    build: .
    container_name: syslog-analyzer
    ports:
      - "8080:8080"
    environment:
      - TZ=Asia/Shanghai
      - LOG_ROOT=/logs
      - RULES_FILE=/app/rules.yaml
      - ENABLE_AI=${ENABLE_AI:-false}
      - OPENAI_API_KEY=${OPENAI_API_KEY:-}
      - OPENAI_BASE_URL=${OPENAI_BASE_URL:-https://api.deepseek.com}
      - OPENAI_MODEL=${OPENAI_MODEL:-deepseek-v4-flash}
      - AI_TIMEOUT_SECONDS=${AI_TIMEOUT_SECONDS:-90}
    volumes:
      - /volume1/docker/syslog/log:/logs:ro
    restart: unless-stopped
```

如果你的日志目录不同，请修改 volume 左侧路径；容器内路径保持 `/logs`。

## 启用 AI 分析

AI 默认关闭。启用后，页面会出现可用的“AI 分析当前日志”按钮。

后端只会发送用户当前筛选条件下的最近 N 行日志，并在发送前自动脱敏：

- IP
- MAC
- 账号
- SN/序列号
- 手机号

在部署目录创建 `.env`：

```bash
cat > .env <<'EOF'
ENABLE_AI=true
OPENAI_API_KEY=你的 API Key
OPENAI_BASE_URL=https://api.deepseek.com
OPENAI_MODEL=deepseek-v4-flash
AI_TIMEOUT_SECONDS=90
EOF
```

重启：

```bash
docker compose up -d --build
```

检查状态：

```bash
curl http://127.0.0.1:8080/health
```

注意：不要把 `.env` 提交到 GitHub。

## 规则库

规则文件是 `rules.yaml`。

每条规则至少包含：

```yaml
- id: custom_rule
  pattern: '\byour regex here\b'
  severity: warning
  category: custom_category
  chinese_summary: 中文解释
  suggestion: 处理建议
```

字段说明：

- `pattern`：正则表达式，忽略大小写。
- `severity`：`critical`、`error`、`warning`、`info`。
- `category`：分类，自动分析会根据分类聚合问题。
- `chinese_summary`：日志明细表展示的中文解释。
- `suggestion`：单条日志层面的处理建议。

修改规则后重启容器：

```bash
docker compose restart syslog-analyzer
```

## 已内置的识别类型

网络与系统：

- link down / link up
- port flapping
- reboot / restart / watchdog
- kernel panic / oops / crash
- WAN down
- PPPoE down
- DHCP failed / 地址池耗尽
- DNS failed
- NTP 异常
- VPN 异常
- 防火墙拒绝/丢弃
- Wi-Fi 终端断开
- IP/ARP 冲突
- 接口 CRC/丢包/协商错误
- 存储空间或文件系统异常
- CPU/内存压力
- 温度、风扇、电源异常

NAS 审计与运维：

- SMB 文件访问成功/失败
- SMB/Samba 服务连接异常
- NAS 登录成功/失败
- SSH 会话断开
- sudo/su 管理命令
- NAS 配置、共享、权限、账号、服务变更
- 传输、同步、下载、备份任务状态和失败
- 存储、磁盘、卷、RAID 状态变化和异常
- UPS/电池/供电告警
- Docker/容器状态和异常

## 自动分析逻辑

程序会按时间窗口和分类聚合日志，识别例如：

- 短时间多次 `reboot/restart/watchdog`：设备疑似异常重启。
- `WAN down` 后出现 `PPPoE down` 或 `DHCP failed`：外网链路或运营商接入异常。
- 同一接口反复 `link up/down`：链路抖动。
- 多次 `DNS failed`：DNS 解析异常。
- `thermal/fan/power`：硬件或环境告警。
- 连续认证失败：密码错误或异常登录尝试。
- `kernel panic/oops/crash`：内核、驱动或固件异常。
- NAS 传输失败：同步/下载/备份任务异常。
- NAS 配置失败：权限、共享、账号或服务设置没有成功生效。
- NAS 存储告警：磁盘、卷、RAID 或文件系统需要优先检查。

每个问题会输出：

- 问题标题
- 严重级别
- 发生时间范围
- 涉及设备
- 相关原始日志
- 中文解释
- 可能原因
- 建议处理步骤

## API

```text
GET /health
GET /api/files
GET /api/logs?file=messages&limit=500&keyword=pppoe
GET /api/logs?file=remote/router/2026-07-09.log&limit=1000&device=router&severity=warning
GET /api/analyze?file=messages&limit=2000
GET /api/summary
GET /api/ai-analyze?file=messages&limit=500&severity=warning
GET /api/rules
```

说明：

- `file` 必须是 `/logs` 下的相对路径。
- 不允许绝对路径。
- 不允许 `../../` 路径穿越。
- `/api/ai-analyze` 只有在 `ENABLE_AI=true` 且配置了 `OPENAI_API_KEY` 后可用。

## syslog-ng 日志落盘建议

推荐宿主机目录：

```text
/volume1/docker/syslog/log
```

推荐落盘文件：

```text
/volume1/docker/syslog/log/messages
/volume1/docker/syslog/log/messages-kv.log
/volume1/docker/syslog/log/remote/${HOST}/${YEAR}-${MONTH}-${DAY}.log
```

容器映射：

```yaml
volumes:
  - /volume1/docker/syslog/log:/logs:ro
```

如果 syslog-ng 本身也是 Docker 容器，建议：

- UDP 514 映射到 syslog-ng 容器的 UDP 接收端口。
- TCP 601 映射到 syslog-ng 容器的 TCP 接收端口。
- 日志目录统一写到 `/volume1/docker/syslog/log`。
- 分析器只读挂载日志目录，避免误写。

## NAS 日志接入建议

NAS 本机可以通过 rsyslog 转发一份日志到 syslog-ng。

推荐保留：

- `smbd_audit`：谁访问了哪个共享文件。
- `sshd` / `ug_login`：谁登录了 NAS。
- `sudo` / `su`：谁执行了管理命令。
- `conf_tool` / `ugos_serv` / `filemgr_serv`：谁修改了配置、共享、权限、账号。
- `syncbackup_serv` / `xunlei_serv` / `rsync` / `rclone`：传输、下载、同步、备份。
- `storage_serv` / `mdadm` / `smartd`：存储、磁盘、RAID、SMART。
- `usbhid-ups` / `upsd` / `upsmon`：UPS。
- `docker_serv` / `dockerd` / `containerd`：容器。

本项目默认会在 Web/API 层隐藏直接包含以下路径的自维护噪声：

```text
/volume1/docker/syslog
/volume1/docker/syslog-analysis
/volume1/docker/syslog-analyzer
```

如需调整，设置环境变量：

```bash
AUDIT_PATH_EXCLUDES=/volume1/docker/syslog,/volume1/docker/syslog-analysis,/volume1/docker/syslog-analyzer
```

## 无法读取日志的排查

确认宿主机目录存在：

```bash
ls -lah /volume1/docker/syslog/log
```

确认容器能看到 `/logs`：

```bash
docker exec -it syslog-analyzer sh -lc "ls -lah /logs && find /logs -maxdepth 3 -type f | head"
```

查看健康检查：

```bash
curl http://127.0.0.1:8080/health
```

查看容器日志：

```bash
docker logs --tail=200 syslog-analyzer
```

确认 compose 的挂载是只读：

```yaml
- /volume1/docker/syslog/log:/logs:ro
```

如果 `/health` 显示 `log_root_exists: false`，说明容器内没有看到 `/logs`，优先检查宿主机路径和 volume 映射。

## 安全说明

- 程序不需要登录，适合局域网内使用。
- 默认监听 `0.0.0.0:8080`。
- 日志目录以只读方式挂载。
- API 会阻止路径穿越。
- AI 分析默认关闭。
- `.env`、API Key、密码、真实密钥不应提交到仓库。

## 本地开发

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
LOG_ROOT=/path/to/syslog/log uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

浏览器打开：

```text
http://127.0.0.1:8080
```
