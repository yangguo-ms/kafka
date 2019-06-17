import azpubsub.kafka.security.authenticator.SaslAuthenticationContextValidator;
import azpubsub.kafka.security.authenticator.SslAuthenticationContextValidator;
import kafka.server.KafkaConfig;
import org.apache.kafka.common.security.authenticator.AzPubSubPrincipalBuilder;
import org.apache.kafka.common.utils.Utils;
import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.easymock.PowerMock;
import org.powermock.api.support.membermodification.MemberMatcher;
import org.powermock.api.support.membermodification.MemberModifier;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;


@RunWith(PowerMockRunner.class)
@PrepareForTest(Utils.class)
public class AzPubSubPrincipalBuilderTest {
    private AzPubSubPrincipalBuilder azPubSubPrincipalBuilder = new AzPubSubPrincipalBuilder();
    private java.util.Map<String, Object> configs = new java.util.HashMap<String, Object>();
    private SslAuthenticationContextValidator sslAuthenticationContextValidator = EasyMock.createNiceMock(SslAuthenticationContextValidator.class);
    private SaslAuthenticationContextValidator saslAuthenticationContextValidator = EasyMock.createNiceMock(SaslAuthenticationContextValidator.class);

    @Before
    public void setUp() {
        configs.put("azpubsub.ssl.authentication.validator.class", "mocksslauthenticationvalidatorclass");
        configs.put("azpubsub.sasl.authentication.validator.class", "mocksaslauthenticationvalidatorclass");

        PowerMock.mockStatic(Utils.class);
    }

    @Test
    public void testConfigure() {
        MemberModifier.suppress(MemberMatcher.methodsDeclaredIn(Logger.class));

//        EasyMock.expect(Utils.newInstance(Class))
    }
}
