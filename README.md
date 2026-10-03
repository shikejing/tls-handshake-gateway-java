# TLS Handshake Gateway

基于本地回环（127.0.0.1）的双向 TLS 握手通道，供内部服务之间互相验证身份。
每个入站/出站连接都执行完整的对端证书校验，并统一管控固定凭据（public key
pinning）、吊销状态与会话复用。实现位于
`src/main/java/com/github/shikejing/tlshandshakegatewayjava/gateway/`。

## 组件

| 类 | 职责 |
| --- | --- |
| `HandshakeGateway` | 回环上的 mTLS 服务端/客户端；握手后复核对端链 |
| `PolicyManager` | 以 `AtomicReference` 持有当前 `SecurityPolicy`，更新原子生效 |
| `SecurityPolicy` | 不可变策略快照：信任锚、中间证书、固定指纹、吊销配置 |
| `PeerVerifier` | 对一条对端证书链执行全部校验 |
| `GatewayTrustManager` | JSSE 信任管理器，握手期间委托 `PeerVerifier` |
| `FileRevocationSource` | 本地文件吊销数据源（十六进制序列号，一行一个） |
| `FailureReason` | 可机器区分的失败原因枚举 |

## 校验语义

`PeerVerifier.verify(chain, peerName)` 按以下顺序校验，任一失败即拒绝握手，
并抛出携带具体 `FailureReason` 的 `HandshakeVerificationException`：

1. **信任链**：从叶子证书出发，用对端出示的证书与策略中配置的中间证书
   逐级构建到配置的信任锚，逐级验证签名。可区分：
   - `CHAIN_INCOMPLETE`：找不到签发者（对端缺中间证书）；
   - `SIGNATURE_INVALID`：找到候选签发者但签名验证失败；
   - `UNTRUSTED_ROOT`：链终止于不在信任锚集合中的自签证书。
2. **有效期**：链上每张证书都必须在有效期内，否则
   `CERT_EXPIRED` / `CERT_NOT_YET_VALID`。
3. **基本约束**：链上除叶子外的每张证书必须是 CA
   （`basicConstraints: CA=true`），否则 `BASIC_CONSTRAINTS_VIOLATION`。
4. **密钥用途**：叶子证书 `keyUsage` 须允许 `digitalSignature`，CA 证书
   须允许 `keyCertSign`（扩展缺省视为不限制），否则 `KEY_USAGE_MISMATCH`。
5. **扩展密钥用途与角色匹配**：本端作为服务端时，对端证书 EKU 必须包含
   `clientAuth`；本端作为客户端时必须包含 `serverAuth`。只能用于服务端
   身份的证书无法通过客户端认证，反之亦然（`EXTENDED_KEY_USAGE_MISMATCH`）。
6. **公开密钥固定**：若为该对端名配置了指纹集合，叶子证书的
   SubjectPublicKeyInfo 的 SHA-256（小写十六进制）必须命中其中之一。
   可配置多个指纹以支持密钥轮换。失败（`PIN_MISMATCH`）信息不包含对端
   证书内容与实际指纹，避免泄露。
7. **吊销检查**：若配置了 `RevocationSource`，链上除信任锚外的每张证书
   都会查询吊销状态，被吊销即拒绝（`CERT_REVOKED`）。数据源不可用时按
   `RevocationPolicy` 处理：
   - `FAIL_CLOSED`（默认）：拒绝握手（`REVOCATION_STATUS_UNAVAILABLE`），
     攻击者无法通过破坏吊销源绕过吊销；
   - `FAIL_OPEN`：放行并记录警告日志，牺牲安全换可用性。

## 会话复用

JSSE 会话复用（TLS 1.3 session ticket）下，缩写握手不会触发信任管理器。
因此 `HandshakeGateway` 在**每次握手完成后**（包括复用的会话）都用当前
生效的策略快照对 `SSLSession` 中的对端链重新完整校验。固定凭据或信任
配置更新后，旧会话无法绕过新要求——复用的连接会在握手后复核阶段被拒绝
并关闭。

## 配置热更新与并发

- `SecurityPolicy` 不可变；`PolicyManager.update()` 整体替换快照，对新建
  连接原子生效。
- 单次握手只使用一份快照，不会观察到半新半旧的策略；已建立的连接不受
  更新影响（TLS 层校验已在建立时完成）。
- `FileRevocationSource` 依据文件 mtime 缓存并原子切换内容快照，文件更新
  无需重启即可生效。
- 全部共享状态均为不可变对象或并发容器；高并发握手与频繁更新互不影响，
  单个连接的失败不会污染其他连接。

## 使用示例

```java
SecurityPolicy policy = SecurityPolicy.builder()
        .trustAnchors(Set.of(rootCa))
        .intermediates(Set.of(intermediateCa))
        .pinsByPeer(Map.of("orders-service", Set.of(pinOld, pinNew))) // 轮换
        .revocationSource(new FileRevocationSource(Path.of("revoked.txt")))
        .revocationPolicy(RevocationPolicy.FAIL_CLOSED)
        .build();
PolicyManager manager = new PolicyManager(policy);

HandshakeGateway gateway = new HandshakeGateway(manager);
int port = gateway.listen(serverIdentity, "clients", (socket, peerChain) -> {
    // 处理已验证的连接
});
try (SSLSocket socket = gateway.connect(clientIdentity, "orders-service", port)) {
    // ...
}

// 运行中热更新：对新连接原子生效
manager.update(newPolicy);
```

## 吊销文件格式

```
# 注释以 # 开头；每行一个被吊销证书的序列号（十六进制，大小写不敏感）
0a1b2c3d
4f5e6d7c
```

文件缺失或不可读视为数据源不可用，由 `RevocationPolicy` 决定放行或拒绝。

## 测试

```
mvn test
```

覆盖：信任链失败（缺中间证书/签名无效/根不受信）、有效期与用途不符、
指纹不匹配与轮换、吊销（含 FAIL_CLOSED/FAIL_OPEN）、会话复用受新策略
约束、信任配置热更新、以及高并发握手叠加频繁策略更新的正确性。
