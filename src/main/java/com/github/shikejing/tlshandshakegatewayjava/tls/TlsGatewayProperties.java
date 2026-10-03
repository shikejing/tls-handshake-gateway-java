package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 握手通道可配置项（application.properties 中前缀 tls.gateway）。
 */
@ConfigurationProperties(prefix = "tls.gateway")
public class TlsGatewayProperties {

    /** 本端角色：server 或 client。 */
    private String role = "server";

    /** 握手通道监听端口，0 表示随机分配。 */
    private int port = 0;

    /** 策略文件热更新轮询间隔（毫秒）。 */
    private long watchIntervalMs = 1000;

    /** 策略文件路径；为空时使用内嵌默认策略。 */
    private String policyFile;

    /** 吊销状态本地数据源文件路径。 */
    private String revocationFile;

    /** 数据源不可用时的策略：fail-closed 或 fail-open。 */
    private String revocationUnavailablePolicy = "fail-closed";

    /** 是否启用公钥固定。 */
    private boolean pinningEnabled = true;

    /** 是否启用吊销检查。 */
    private boolean revocationEnabled = true;

    /** 是否允许会话复用。 */
    private boolean sessionResumptionEnabled = true;

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    public long getWatchIntervalMs() { return watchIntervalMs; }
    public void setWatchIntervalMs(long v) { this.watchIntervalMs = v; }
    public String getPolicyFile() { return policyFile; }
    public void setPolicyFile(String policyFile) { this.policyFile = policyFile; }
    public String getRevocationFile() { return revocationFile; }
    public void setRevocationFile(String revocationFile) { this.revocationFile = revocationFile; }
    public String getRevocationUnavailablePolicy() { return revocationUnavailablePolicy; }
    public void setRevocationUnavailablePolicy(String v) { this.revocationUnavailablePolicy = v; }
    public boolean isPinningEnabled() { return pinningEnabled; }
    public void setPinningEnabled(boolean pinningEnabled) { this.pinningEnabled = pinningEnabled; }
    public boolean isRevocationEnabled() { return revocationEnabled; }
    public void setRevocationEnabled(boolean revocationEnabled) { this.revocationEnabled = revocationEnabled; }
    public boolean isSessionResumptionEnabled() { return sessionResumptionEnabled; }
    public void setSessionResumptionEnabled(boolean v) { this.sessionResumptionEnabled = v; }
}
