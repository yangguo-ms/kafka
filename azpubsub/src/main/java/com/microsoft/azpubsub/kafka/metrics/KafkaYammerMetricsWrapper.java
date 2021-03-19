package com.microsoft.azpubsub.kafka.metrics;

import com.yammer.metrics.core.MetricsRegistry;
import kafka.metrics.KafkaYammerMetrics;

public class KafkaYammerMetricsWrapper {
    public static MetricsRegistry defaultRegistry() {
        return KafkaYammerMetrics.defaultRegistry();
    }
}
