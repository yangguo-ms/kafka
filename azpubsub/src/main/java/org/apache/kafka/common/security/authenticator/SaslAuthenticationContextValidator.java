package org.apache.kafka.common.security.authenticator;

import javax.security.sasl.SaslServer;

public interface SaslAuthenticationContextValidator {
    void configure(java.util.Map<String, ?> props);
    AzPubSubPrincipal authenticate(SaslServer saslServer);
}
