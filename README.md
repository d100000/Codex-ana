# PlanScope · Codex 订阅光谱

PlanScope 是一个只在本机运行的 Codex 中转池采样工具。用户填写兼容 OpenAI API 的地址和 API Key 后，它会执行 100 个逻辑样本，并按照接口实际返回的 tier 动态统计订阅等级比例。

## 模型读取与选择

每次分析前，先点击“读取模型”。服务会请求当前地址的 `GET /v1/models`，把可用于本次分析的模型 ID 放入下拉框：

- 默认推荐顺序是精确的 `gpt-5.5`，其次是精确的 `gpt-5.4`
- 用户可以在每次分析前改选列表中的任意模型
- 创建任务后，服务端会重新读取模型列表并核验所选 ID，避免使用已经下线的模型
- 如果中转没有实现模型列表接口，页面会明确显示“兼容候选”，不会把候选项冒充成接口实测结果

## 它如何判定订阅

每个样本向非流式 `POST /v1/responses` 发送一条极短请求。判定优先级为：

1. 响应头 `x-codex-plan-type`
2. 响应体 `plan_type` 或 `planType`
3. 响应体 `error.plan_type` / `error.planType`
4. 响应体 `rate_limits.plan_type` / `rateLimits.planType`

同时保留 `x-codex-active-limit`、主/次限额窗口、Credits 状态和上游请求 ID，供逐条核验。正常响应中没有以上订阅字段时，该样本记为“未识别”，不会仅凭模型名称或额度猜测订阅。

订阅等级没有白名单。Pro、Plus、Team、K12 或任何未来新增的非空 tier 都会自动成为独立分类，并使用动态颜色显示。

探测请求只发送一句 `Reply exactly OK.`，不加载工具，不要求推理摘要，输出上限为 16 tokens；支持无推理模式的模型会使用 `reasoning.effort: none`，其他模型回退到其低开销档位。

## 固定采样策略

- 100 个逻辑样本
- 最大并发 50
- 每个失败样本最多尝试 5 次
- 只有网络错误、超时、408、409、425、429、500、502、503、504 会重试
- 每次重试前随机等待 1–3 秒
- 首个样本先单独验证，成功后才放出剩余并发
- 每个逻辑样本使用独立会话标识；同一样本的重试复用标识

这里的百分比是该地址在本次 100 个样本中的**路由观测分布**，不等同于中转池真实账号库存。中转站若固定会话、缓存请求或不透传 Codex 头部，结果也会受到影响。

## 防滥用保护

每次启动分析前都必须完成一次滑块验证。滑块挑战由服务端生成并验证，具有以下约束：

- 挑战与当前 IP、匿名设备 Cookie 绑定，2 分钟后过期
- 拖动位置、持续时间和轨迹采样均由服务端复核
- 通过后签发短期一次性凭证，使用后立即失效
- 成功启动分析后，IP 和设备两个维度分别进入 5 分钟冷却；任一维度仍在冷却都会返回 HTTP `429`
- 模型列表接口同样按 IP 和设备限流，默认每 5 分钟最多读取 6 次，防止被用于批量测试 Key
- 设备 Cookie 使用 `HttpOnly`、`SameSite=Strict`，HTTPS 公网模式下增加 `Secure` 与 `__Host-` 前缀
- 内存中只保存经过 HMAC 处理的 IP/设备键，不保存原始 IP
- 分析任务与创建任务的设备绑定；其他设备即使获得任务 ID，也不能读取进度或取消任务

滑块是提高自动化成本的纵深防御，不是不可破解的身份认证。当前限流状态保存在单个 Node.js 进程内，服务重启会清空；如果部署多个实例，应把挑战和冷却状态迁移到 Redis 等共享存储，并在入口继续配置 CDN/WAF 限流。

默认不信任代理转发的 IP 头。开启代理模式后，也只接受来自回环地址或 `TRUSTED_PROXY_IPS` 的转发头，并且只读取一个显式指定的 IP Header。仅当代理会覆盖客户端提供的同名 Header 时，才设置：

```bash
TRUST_PROXY=1 \
TRUSTED_PROXY_IPS=10.0.0.10 \
FORWARDED_IP_HEADER=x-real-ip \
npm start
```

## 上游网络安全

所有携带 API Key 的上游请求都会经过专用安全请求器：

- 默认只允许 HTTPS 和 443 端口，避免 Key 经明文 HTTP 传输
- 域名解析出的全部地址都必须是公网地址；回环、RFC 1918、链路本地、共享地址、组播、保留地址及云元数据网段都会被拒绝
- 通过校验后，将实际连接固定到已验证的 IP，降低 DNS 重绑定风险
- 不跟随任何上游重定向，避免 Key 被转发到另一个地址
- 上游响应体最大 512 KiB，响应头和请求体也有独立上限
- 可使用 `ALLOWED_UPSTREAM_HOSTS` 配置精确域名白名单，使用 `ALLOWED_UPSTREAM_PORTS` 显式放行额外端口

如确实需要分析本机或内网上游，必须主动开启高风险兼容选项：

```bash
ALLOW_HTTP_UPSTREAMS=1 \
ALLOW_PRIVATE_UPSTREAMS=1 \
ALLOWED_UPSTREAM_PORTS=4318 \
npm start
```

不要在公网部署中开启 `ALLOW_PRIVATE_UPSTREAMS`。

## HTTP 与浏览器边界

- 默认只接受 `127.0.0.1`、`localhost` 和 `[::1]` 的正确 Host，阻止利用本地服务的 DNS 重绑定请求
- 所有修改状态的 API 都要求同源操作标识；跨站 Fetch Metadata、错误 Origin 和简单表单 Content-Type 会被拒绝
- 启用了严格 CSP、COOP、CORP、Permissions Policy、禁止嵌入、禁止 MIME 猜测和 HTTPS 下的 HSTS
- JSON 请求最大 64 KiB；HTTP Header、请求读取时间、连接数及单连接请求数均有限制
- 默认最多同时运行 2 个分析任务、4 个模型读取请求，每个任务最多保留 3 条实时进度连接

只有完全隔离的测试环境才可用 `ALLOW_INSECURE_PUBLIC_ORIGIN=1` 绕过公网 HTTPS 启动检查。

## 启动

需要 Node.js 20 或更高版本，不需要安装第三方依赖。

```bash
npm start
```

打开 <http://127.0.0.1:4317>，填写接口地址和 API Key，读取并选择模型后开始分析。

## 本地演示

终端一：

```bash
npm run mock
```

终端二：

```bash
ALLOW_HTTP_UPSTREAMS=1 \
ALLOW_PRIVATE_UPSTREAMS=1 \
ALLOWED_UPSTREAM_PORTS=4318 \
npm start
```

浏览器中填写：

- 地址：`http://127.0.0.1:4318`
- Key：`sk-test-local`

点击“读取模型”会看到多个候选并默认选中 `gpt-5.5`。模拟上游还会返回多种动态 tier，并让 4 个样本先失败一次，用于验证未知等级统计与随机重试。

## 测试

```bash
npm run check
```

测试覆盖 URL 归一化、模型推荐与复核、字段优先级、额度证据提取、百分比分母、并发上限、随机重试、私网地址识别、DNS 固定、跨站防护和接口限流。自动化测试只调用内存模拟接口，不会使用真实 API Key 或消耗上游额度。

需要监听本机测试端口的完整安全集成测试：

```bash
npm run test:security
```

它会验证 DNS 重绑定 Host、跨站请求、错误 Content-Type、云元数据地址拦截，以及任务的设备访问隔离。

## 密钥与部署安全

- 服务默认只监听 `127.0.0.1`。
- API Key 不写入文件、浏览器存储、任务快照、导出文件或日志；上游即使在错误或元数据中回显 Key 也会被脱敏，任务结束后会从任务凭据对象中清空。
- 匿名设备标识只存在于受保护 Cookie 中，页面脚本无法读取。
- CSV 导出会中和由上游字段带入的公式前缀，降低用表格软件打开时的公式注入风险。
- 上游重定向不会被自动跟随，避免将 Key 转发到另一个域名。
- 非本机监听默认必须配置 HTTPS 的 `PUBLIC_ORIGIN`，否则服务拒绝启动；直连 HTTP 也会返回 `426`。反向代理必须从受信地址发送 `X-Forwarded-Proto: https`，`ALLOWED_HOSTS` 可用于补充精确 Host 别名。
- 公网部署建议同时设置 `ALLOWED_UPSTREAM_HOSTS`，并在入口继续配置 HTTPS、认证、CDN/WAF 限流和请求日志脱敏。
- 当前挑战、限流和任务状态仍保存在单进程内存中；多实例部署必须迁移到 Redis 等共享存储。
- 100 个逻辑样本在极端情况下最多产生 500 次 Responses 请求，请先确认额度、费率限制和服务条款。

公网反向代理示例：

```bash
HOST=0.0.0.0 \
PUBLIC_ORIGIN=https://planscope.example.com \
TRUST_PROXY=1 \
TRUSTED_PROXY_IPS=127.0.0.1 \
FORWARDED_IP_HEADER=x-real-ip \
ABUSE_SECRET='至少 32 字节的随机值' \
ALLOWED_UPSTREAM_HOSTS=api.example.com \
npm start
```
