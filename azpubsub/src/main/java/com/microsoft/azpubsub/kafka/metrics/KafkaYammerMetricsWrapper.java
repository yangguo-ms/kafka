package com.microsoft.azpubsub.kafka.metrics;

import com.yammer.metrics.Metrics;
import com.yammer.metrics.core.MetricsRegistry;

public class KafkaYammerMetricsWrapper {
    public static MetricsRegistry defaultRegistry() {
        return Metrics.defaultRegistry();
    }
}