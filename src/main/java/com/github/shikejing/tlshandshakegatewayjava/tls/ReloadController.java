package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Path;
import java.util.Map;

/**
 * 提供运行中热更新入口：重新加载策略文件并原子替换。
 */
@RestController
@RequestMapping("/admin/tls")
public class ReloadController {

    private static final Logger log = LoggerFactory.getLogger(ReloadController.class);

    private final PolicyManager policyManager;
    private final PolicyFileLoader loader;

    public ReloadController(PolicyManager policyManager, TlsGatewayProperties properties) {
        this.policyManager = policyManager;
        this.loader = properties.getPolicyFile() == null
                ? null
                : new PolicyFileLoader(Path.of(properties.getPolicyFile()));
    }

    @PostMapping("/reload")
    public Map<String, Object> reload() {
        if (loader != null) {
            policyManager.reload(loader.load());
        }
        return Map.of("epoch", policyManager.epoch());
    }
}
