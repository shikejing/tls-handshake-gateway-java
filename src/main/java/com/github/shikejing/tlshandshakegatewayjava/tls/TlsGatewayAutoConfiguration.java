package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;

import java.nio.file.Path;
import java.time.Duration;

/**
 * 握手通道自动配置：加载策略文件、构建策略管理器、启动服务端并注册热更新轮询。
 */
@Configuration
@EnableConfigurationProperties(TlsGatewayProperties.class)
public class TlsGatewayAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(TlsGatewayAutoConfiguration.class);

    @Bean
    public PolicyManager policyManager(TlsGatewayProperties properties) {
        if (properties.getPolicyFile() != null && !properties.getPolicyFile().isBlank()) {
            try {
                PolicyFileLoader loader = new PolicyFileLoader(Path.of(properties.getPolicyFile()));
                return new PolicyManager(loader.load());
            } catch (RuntimeException e) {
                log.warn("无法加载策略文件 {}，使用空策略: {}", properties.getPolicyFile(), e.toString());
            }
        }
        log.warn("未配置 tls.gateway.policy-file，使用空策略（仅测试用途）");
        return new PolicyManager(PolicyConfig.builder().build());
    }

    @Bean
    public PolicyFileWatcher policyFileWatcher(PolicyManager policyManager,
                                                TlsGatewayProperties properties) {
        if (properties.getPolicyFile() == null || properties.getPolicyFile().isBlank()) {
            return null;
        }
        PolicyFileLoader loader = new PolicyFileLoader(Path.of(properties.getPolicyFile()));
        Path revFile = properties.getRevocationFile() == null ? null
                : Path.of(properties.getRevocationFile());
        return new PolicyFileWatcher(policyManager, loader, revFile,
                Duration.ofMillis(properties.getWatchIntervalMs()));
    }

    @Bean
    public HandshakeGateway handshakeGateway(PolicyManager policyManager,
                                             TlsGatewayProperties properties) {
        return new HandshakeGateway(policyManager, properties.getPort());
    }

    @EventListener(ApplicationReadyEvent.class)
    public void start(ApplicationReadyEvent event) throws Exception {
        event.getApplicationContext().getBean(HandshakeGateway.class).start();
        PolicyFileWatcher watcher = event.getApplicationContext().getBeanProvider(PolicyFileWatcher.class)
                .getIfAvailable();
        if (watcher != null) {
            watcher.start();
        }
    }
}
