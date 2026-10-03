# 本地回环安全握手通道（TLS Handshake Gateway）

基于本地回环（loopback）的双向证书认证握手通道，对每个入站连接做双向证书校验，
供内部服务之间互相验证身份。在校验身份的同时统一管控固定凭据、吊销状态和会话复用。

## 架构

```
┌─────────────┐                  ┌─────────────┐
│  客户端服务  │  TLS 1.2 双向认证  │  服务端网关  │
│ Handshake   │◄────────────────►│ Handshake   │
│ Client      │   127.0.0.1:port │ Gateway     │
└─────────────┘                  └─────────────┘
```

- **HandshakeGateway**：服务端，监听本地回环端口，对每个入站连接执行双向证书校验，通过后提供回显服务。
- **HandshakeClient**：客户端，连接服务端并执行双向证书校验。
- **PolicyManager**：策略管理器，以原子引用保存当前策略快照，支持运行中热更新。
- **PolicySnapshot**：不可变策略快照。一次握手从开始到结束始终使用同一个快照，
  因此进行中的握手不会处于"半新半旧"的策略之下。
- **ValidatingTrustManager**：自定义 TrustManager，在握手阶段调用 CertificateValidator。
- **CertificateValidator**：核心校验器，依次执行链信任、有效期、用途、基本约束、公钥固定、吊销状态校验。

## 校验语义

对端证书链（叶子在前）依次通过以下校验，任一失败即拒绝：

1. **证书链信任**（`CHAIN_MISSING_INTERMEDIATE` / `CHAIN_UNTRUSTED_ROOT` / `SIGNATURE_INVALID`）
   - 逐张验证链上签名关系：叶子由中间 CA 签名，中间 CA 由根 CA 签名。
   - 链缺中间证书（无法构建到信任锚的路径）→ `CHAIN_MISSING_INTERMEDIATE`。
   - 链终结于不受信的根证书 → `CHAIN_UNTRUSTED_ROOT`。
   - 证书签名无法用颁发者公钥验证 → `SIGNATURE_INVALID`。
   - 双方各自依据配置的信任锚验证对方的完整证书链。

2. **有效期**（`CERT_EXPIRED` / `CERT_NOT_YET_VALID`）
   - 检查链上每张证书的 `notBefore` / `notAfter`。

3. **密钥用途与角色匹配**（`ROLE_MISMATCH`）
   - 本端为服务端时，对端证书必须具备客户端身份（EKU `clientAuth`，密钥用途含 `digitalSignature`）。
   - 本端为客户端时，对端证书必须具备服务端身份（EKU `serverAuth`，密钥用途含 `digitalSignature` 或 `keyEncipherment`）。
   - 仅具备服务端身份的证书不得通过客户端认证，反之亦然。

4. **基本约束**（`END_ENTITY_IS_CA` / `CHAIN_BASIC_CONSTRAINTS_INVALID`）
   - 终端证书不得带有 CA 基本约束。
   - 中间证书必须具备 CA 基本约束。

5. **公开密钥固定**（`PIN_MISMATCH` / `PIN_NOT_CONFIGURED`）
   - 固定对端证书的 SPKI SHA-256 指纹（`sha256:<hex>`）。
   - 允许为一个对端（按 CN 标识）配置多个可接受指纹以便轮换。
   - 指纹与配置全部匹配不上时拒绝，失败信息不泄露证书完整内容。

6. **吊销状态**（`CERT_REVOKED` / `REVOCATION_DATA_UNAVAILABLE`）
   - 吊销状态从本地数据源读取（文件，每行一个被吊销证书序列号，十六进制）。
   - 被吊销的证书在新建连接时必须被拒绝。
   - 数据源不可用时按可配置策略处理（见下文）。

7. **会话复用**
   - 支持 TLS 会话复用。恢复的会话在建立后仍按当前生效的策略快照复核对端证书。
   - 固定凭据或信任配置发生变化后，旧会话不得绕过新的校验要求。

## 失败原因码

| 原因码 | 含义 |
|--------|------|
| `CHAIN_MISSING_INTERMEDIATE` | 证书链缺少中间证书 |
| `CHAIN_UNTRUSTED_ROOT` | 证书链终结于不受信的根 |
| `SIGNATURE_INVALID` | 证书签名无法验证 |
| `CERT_EXPIRED` | 证书已过有效期 |
| `CERT_NOT_YET_VALID` | 证书尚未生效 |
| `ROLE_MISMATCH` | 证书用途与当前角色不匹配 |
| `END_ENTITY_IS_CA` | 终端证书带有 CA 身份 |
| `CHAIN_BASIC_CONSTRAINTS_INVALID` | 中间证书不具备 CA 基本约束 |
| `PIN_MISMATCH` | 公钥指纹与固定凭据均不匹配 |
| `PIN_NOT_CONFIGURED` | 未配置对端的固定凭据 |
| `CERT_REVOKED` | 证书已被吊销 |
| `REVOCATION_DATA_UNAVAILABLE` | 吊销数据源不可用且策略为拒绝 |
| `NO_PEER_CERTIFICATE` | 对端未提供证书 |
| `VALIDATION_ERROR` | 其他校验异常 |

## 吊销数据源不可用策略

| 策略 | 后果 |
|------|------|
| `fail-closed`（默认） | 数据源不可用时拒绝所有握手。更安全，但可用性下降——数据源故障期间所有新连接被拒。 |
| `fail-open` | 数据源不可用时放行。可用性优先，但被吊销证书可能蒙混过关——存在安全风险。 |

## 可配置项

### application.properties

```properties
# 本端角色：server 或 client
tls.gateway.role=server
# 握手通道监听端口（0 表示随机分配）
tls.gateway.port=0
# 策略文件路径
tls.gateway.policy-file=./tls-policy.properties
# 吊销数据文件路径（也可在策略文件中指定）
tls.gateway.revocation-file=./revoked.txt
# 数据源不可用策略：fail-closed 或 fail-open
tls.gateway.revocation-unavailable-policy=fail-closed
# 是否启用公钥固定
tls.gateway.pinning-enabled=true
# 是否启用吊销检查
tls.gateway.revocation-enabled=true
# 是否允许会话复用
tls.gateway.session-resumption-enabled=true
# 策略文件热更新轮询间隔（毫秒）
tls.gateway.watch-interval-ms=1000
```

### 策略文件（tls-policy.properties）

```properties
# 本端角色
role=server

# 本端身份（PKCS#8 PEM 私钥 + PEM 证书链）
identity.key=keys/server-key.pem
identity.cert=keys/server-cert.pem

# 信任锚（PEM，逗号分隔）
trustAnchors=keys/ca.pem

# 公钥固定：pin.<角色>.<对端CN>=sha256:指纹1,sha256:指纹2
pin.client.internal-client=sha256:aa:bb:cc:dd,sha256:ee:ff:00:11
pin.server.localhost=sha256:11:22:33:44

# 吊销检查
revocation.enabled=true
revocation.file=revoked.txt
revocation.unavailablePolicy=fail-closed

# 公钥固定开关
pinning.enabled=true

# 会话复用开关
sessionResumption.enabled=true
```

### 吊销数据文件（revoked.txt）

```
# 每行一个被吊销证书的序列号（十六进制，可带 0x 前缀）
01ab23cd45ef6789
0x9876543210abcdef
```

## 热更新

- 策略文件或吊销数据文件变化后，`PolicyFileWatcher` 自动检测并原子替换策略快照。
- 更新对之后新建的连接生效；进行中的握手继续使用旧快照；已建立的连接不受影响。
- 也可通过 `POST /admin/tls/reload` 手动触发重新加载。
- 仅当本端身份（密钥/证书）变化时才重建 SSLContext，避免清空会话缓存。

## 并发模型

- 服务端每个连接一个工作线程。
- 每次握手开始时取一次策略快照并绑定到该线程（`ThreadLocal`），整次握手复用同一快照。
- 不同连接使用不同快照，互不污染。
- 策略更新通过原子引用（`AtomicReference`）生效，无线程安全问题。

## 测试

```bash
mvn test
```

测试覆盖：

- **CertificateValidatorTest**：信任链失败（缺中间证书、不受信根、签名无效）、有效期、用途不符、CA 约束、公钥固定（不匹配、未配置、轮换）、吊销（已吊销、数据源不可用 fail-closed/fail-open）。
- **HandshakeGatewayIT**：双向认证成功、各类拒绝场景、会话复用、复用会话在固定凭据变化后被拒、热更新对新连接生效且不影响已建立连接、高并发握手一致性。
- **PolicyFileLoaderTest**：策略文件解析、吊销数据源读取与不可用、策略原子替换。
