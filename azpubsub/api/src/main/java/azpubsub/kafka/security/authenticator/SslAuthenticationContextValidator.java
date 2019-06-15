package azpubsub.kafka.security.authenticator;

import javax.net.ssl.SSLSession;
import java.util.Map;

public interface SslAuthenticationContextValidator {
    void configure(Map<String, ?> props);
    AzPubSubPrincipal authenticate(SSLSession sslSession);
}