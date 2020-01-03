import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.auth.SaslAuthenticationContext;
import org.apache.kafka.common.security.auth.SecurityProtocol;
import org.apache.kafka.common.security.auth.SslAuthenticationContext;
import org.apache.kafka.common.security.authenticator.AzPubSubPrincipalBuilder;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.powermock.api.support.membermodification.MemberMatcher;
import org.powermock.api.support.membermodification.MemberModifier;
import org.slf4j.Logger;
import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslServer;
import java.net.InetAddress;
import java.util.Map;
import java.util.HashMap;

import static org.junit.Assert.assertThrows;

public class AzPubSubPrincipalBuilderTest {
    private final String AzPubSubSslAuthenticationValidatorClass = "azpubsub.ssl.authentication.validator.class";
    private final String AzPubSubSaslAuthenticationValidatorClass = "azpubsub.sasl.authentication.validator.class";
    private final String MockPositiveSslAuthenticationContextValidator = "mockPositiveSslAuthenticationContextValidator";
    private final String MockPositiveSaslAuthenticationValidator = "mockPositiveSaslAuthenticationContextValidator";

    private final String MockSslAuthenticationContextValidatorWithInvalidAuthentication = "mockSslAuthenticationContextValidatorWithInvalidAuthentication";
    private final String MockSaslAuthenticationContextValidatorWithInvalidAuthentication = "mockSaslAuthenticationContextValidatorWithInvalidAuthentication";

    private AzPubSubPrincipalBuilder azPubSubPrincipalBuilder = new AzPubSubPrincipalBuilder();

    @Before
    public void setUp() {

    }

    @Test
    public void testConfigurePositive() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockPositiveSslAuthenticationContextValidator);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockPositiveSaslAuthenticationValidator);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        azPubSubPrincipalBuilder.configure(configs);
    }

    @Test
    public void testConfigureSslContextValidatorClassNotExists() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, "UnknownClass");
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockPositiveSaslAuthenticationValidator);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        assertThrows(IllegalArgumentException.class, () -> azPubSubPrincipalBuilder.configure(configs));
    }

    @Test
    public void testConfigureSaslContextValidatorClassNotExists() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockPositiveSslAuthenticationContextValidator);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, "UnKnownClass");
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        assertThrows(IllegalArgumentException.class, () -> azPubSubPrincipalBuilder.configure(configs));
    }

    @Test
    public void testValidateSslAuthenticationContextPositive() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockPositiveSslAuthenticationContextValidator);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockPositiveSaslAuthenticationValidator);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        SSLSession sslSession = EasyMock.mock(SSLSession.class);
        InetAddress inetAddress =  InetAddress.getLoopbackAddress();

        azPubSubPrincipalBuilder.configure(configs);

        SslAuthenticationContext sslAuthenticationContext = new SslAuthenticationContext(sslSession, inetAddress, SecurityProtocol.SSL.name());
        KafkaPrincipal kafkaPrincipal = azPubSubPrincipalBuilder.build(sslAuthenticationContext);
        assert(kafkaPrincipal.getName().equals("ANONYMOUS"));
        assert(KafkaPrincipal.ANONYMOUS.getPrincipalType().equals(kafkaPrincipal.getPrincipalType()));
        assert(KafkaPrincipal.ANONYMOUS.getName().equals(kafkaPrincipal.getName()));
    }

    @Test
    public void testValidateSaslAuthenticationContextPositive() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockPositiveSslAuthenticationContextValidator);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockPositiveSaslAuthenticationValidator);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        SaslServer saslServer = EasyMock.mock(SaslServer.class);
        InetAddress inetAddress =  InetAddress.getLoopbackAddress();
        azPubSubPrincipalBuilder.configure(configs);

        SaslAuthenticationContext saslAuthenticationContext = new SaslAuthenticationContext(saslServer, SecurityProtocol.SASL_SSL, inetAddress, SecurityProtocol.SSL.name());
        KafkaPrincipal kafkaPrincipal = azPubSubPrincipalBuilder.build(saslAuthenticationContext);
        assert(kafkaPrincipal.getPrincipalType().equals("Token"));
    }

    @Test
    public void testValidateSaslAuthenticationContextInvalidAuthentication() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockPositiveSslAuthenticationContextValidator);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockSaslAuthenticationContextValidatorWithInvalidAuthentication);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        SaslServer saslServer = EasyMock.mock(SaslServer.class);
        InetAddress inetAddress =  InetAddress.getLoopbackAddress();
        azPubSubPrincipalBuilder.configure(configs);

        SaslAuthenticationContext saslAuthenticationContext = new SaslAuthenticationContext(saslServer, SecurityProtocol.SASL_SSL, inetAddress, SecurityProtocol.SSL.name());

        assertThrows(IllegalSaslStateException.class, () -> azPubSubPrincipalBuilder.build(saslAuthenticationContext));
    }

    @Test
    public void testValidateSslAuthenticationContextWithInvalidAuthentication() {
        Map<String, Object> configs = new HashMap<>();

        configs.put(AzPubSubSslAuthenticationValidatorClass, MockSslAuthenticationContextValidatorWithInvalidAuthentication);
        configs.put(AzPubSubSaslAuthenticationValidatorClass, MockPositiveSaslAuthenticationValidator);
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

        SSLSession sslSession = EasyMock.mock(SSLSession.class);
        InetAddress inetAddress =  InetAddress.getLoopbackAddress();

        azPubSubPrincipalBuilder.configure(configs);

        SslAuthenticationContext sslAuthenticationContext = new SslAuthenticationContext(sslSession, inetAddress, SecurityProtocol.SSL.name());

        assertThrows(IllegalStateException.class, () -> azPubSubPrincipalBuilder.build(sslAuthenticationContext));
    }
}
