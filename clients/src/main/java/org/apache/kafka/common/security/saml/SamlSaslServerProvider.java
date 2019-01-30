package org.apache.kafka.common.security.saml;

import java.security.Provider;
import java.security.Security;
import org.apache.kafka.common.security.saml.SamlSaslServer.SamlSaslServerFactory;
public class SamlSaslServerProvider extends Provider {
    private static final long serialVersionUID = 1L;

    @SuppressWarnings("deprecation")
    protected SamlSaslServerProvider() {
        super("Simple SASL/PLAIN Server Provider", 1.0, "Simple SASL/PLAIN Server Provider for Kafka");
        put("SaslServerFactory." + SamlSaslServer.PLAIN_MECHANISM, SamlSaslServerFactory.class.getName());
    }

    public static void initialize() {
        Security.addProvider(new SamlSaslServerProvider());
    }
}
