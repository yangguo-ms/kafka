package org.apache.kafka.common.security.authenticator;

import org.apache.kafka.common.security.auth.*;
import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.security.sasl.SaslServer;
import java.util.Map;


/**
 *  A new Principal Builder used to replace the default provider.
 *  This provider contructs both regular principal (Kafka Principal) and also SAML token principal.
 */
public class AzPubSubPrincipalBuilder implements KafkaPrincipalBuilder, Configurable {
    public static final String ClientCertificateAclString = "client.ceritificate.acl";
    public static final String SslAuthenticationValidatorClassName = "ssl.authentication.validator.class";
    public static final String SaslAuthenticationValidatorClassName = "sasl.authentication.validator.class";

    private static final Logger LOGGER = LoggerFactory.getLogger(AzPubSubPrincipalBuilder.class);
    private Class<?> sslAuthenticationContextValidatorClass = null;
    private Class<?> saslAuthenticationContextValidatorClass = null;
    private SslAuthenticationContextValidator sslAuthenticationContextValidator = null;
    private SaslAuthenticationContextValidator saslAuthenticationContextValidator = null;
    private String clientCertificateAclString = null;

    public void configure(Map<String, ?> configs) {
        sslAuthenticationContextValidatorClass = (Class<?>) configs.get(SslAuthenticationValidatorClassName);

        if(null != sslAuthenticationContextValidatorClass) {
            LOGGER.info("Ssl Authentication Context Validator class is %s", sslAuthenticationContextValidatorClass);

            sslAuthenticationContextValidator = (SslAuthenticationContextValidator) Utils.newInstance(sslAuthenticationContextValidatorClass);

            if (null != sslAuthenticationContextValidator) {
                sslAuthenticationContextValidator.configure(configs);
            }
            else {
                LOGGER.error("Class %s provider by %s cannot be found or initialized", sslAuthenticationContextValidatorClass, SslAuthenticationValidatorClassName);

                throw new IllegalArgumentException("Class " + sslAuthenticationContextValidatorClass + " provided by setting " + SslAuthenticationValidatorClassName + " is not found or cannot be initialized.");
            }
        }

        saslAuthenticationContextValidatorClass = (Class<?>) configs.get(SaslAuthenticationValidatorClassName);

        if (null != saslAuthenticationContextValidatorClass) {

           saslAuthenticationContextValidator = (SaslAuthenticationContextValidator) Utils.newInstance(saslAuthenticationContextValidatorClass);

           if(null != saslAuthenticationContextValidator) {
               saslAuthenticationContextValidator.configure(configs);
           }
           else {
               LOGGER.error("Class %s provided by setting %s cannot be found or initialized.", saslAuthenticationContextValidatorClass, SaslAuthenticationValidatorClassName);

               throw new IllegalArgumentException("Class " + saslAuthenticationContextValidatorClass + " provided by setting " + SaslAuthenticationValidatorClassName + " is not found.");
           }
        }

        clientCertificateAclString = configs.get(ClientCertificateAclString).toString();
    }

    public KafkaPrincipal build(AuthenticationContext context) {

        if ( context instanceof PlaintextAuthenticationContext ) {

            return KafkaPrincipal.ANONYMOUS;
        }
        else if ( context instanceof SslAuthenticationContext ) {

            SslAuthenticationContext sslAuthenticationContext = (SslAuthenticationContext)context;

            if ( null != sslAuthenticationContextValidator ) {

                AzPubSubPrincipal azPubSubPrincipal = sslAuthenticationContextValidator.authenticate(sslAuthenticationContext.session(), clientCertificateAclString);

                return  new KafkaPrincipal(azPubSubPrincipal.getPrincipalType(), azPubSubPrincipal.getPrincipalType());
            }

            if( null == sslAuthenticationContextValidatorClass) {
                LOGGER.error("No class is provided by %s", SslAuthenticationValidatorClassName);

                throw new IllegalArgumentException("No class name is provided by setting " + SslAuthenticationValidatorClassName + " or class path is invalid. ");
            }
            else {
                LOGGER.error("Class %s provider by %s cannot be found or initialized", sslAuthenticationContextValidatorClass, SslAuthenticationValidatorClassName);

                throw new IllegalArgumentException("Class " + sslAuthenticationContextValidatorClass + " provided by setting " + SslAuthenticationValidatorClassName + " is not found or cannot be initialized.");
            }
        }
        else if ( context instanceof SaslAuthenticationContext ) {

            SaslServer saslServer = ((SaslAuthenticationContext) context).server();

            if (null != saslAuthenticationContextValidator ) {

                AzPubSubPrincipal azPubSubPrincipal = saslAuthenticationContextValidator.authenticate(saslServer);

                return new KafkaPrincipal(azPubSubPrincipal.getPrincipalType(), azPubSubPrincipal.getPrincipalName());
            }

            if( null == saslAuthenticationContextValidatorClass) {

                LOGGER.error("No class name provided by setting %s, or class path is invalid.", SaslAuthenticationValidatorClassName);

                throw new IllegalArgumentException("No class name is provided by setting " + SaslAuthenticationValidatorClassName + " or class path is invalid. ");
            }
            else {

                LOGGER.error("Class %s provided by setting %s cannot be found or initialized.", saslAuthenticationContextValidatorClass, SaslAuthenticationValidatorClassName);

                throw new IllegalArgumentException("Class " + saslAuthenticationContextValidatorClass + " provided by setting " + SaslAuthenticationValidatorClassName + " is not found.");
            }
        }
        else {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }
    }
}