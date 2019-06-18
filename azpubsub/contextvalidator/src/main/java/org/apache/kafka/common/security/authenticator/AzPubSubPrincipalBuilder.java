package org.apache.kafka.common.security.authenticator;

import azpubsub.kafka.security.authenticator.AzPubSubPrincipal;
import azpubsub.kafka.security.authenticator.SaslAuthenticationContextValidator;
import azpubsub.kafka.security.authenticator.SslAuthenticationContextValidator;
import kafka.server.KafkaConfig;
import org.apache.kafka.common.errors.IllegalSaslStateException;
import org.apache.kafka.common.errors.InvalidConfigurationException;
import org.apache.kafka.common.security.auth.*;
import org.apache.kafka.common.Configurable;
import org.apache.kafka.common.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.AuthenticationNotSupportedException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.SaslServer;
import java.util.Map;


/**
 *  A new Principal Builder used to replace the default provider.
 *  This provider contructs both regular principal (Kafka Principal) and also SAML token principal.
 */
public class AzPubSubPrincipalBuilder implements KafkaPrincipalBuilder, Configurable {
    private static final Logger LOGGER = LoggerFactory.getLogger(AzPubSubPrincipalBuilder.class);
    private Class<?> sslAuthenticationContextValidatorClass = null;
    private Class<?> saslAuthenticationContextValidatorClass = null;
    private SslAuthenticationContextValidator sslAuthenticationContextValidator = null;
    private SaslAuthenticationContextValidator saslAuthenticationContextValidator = null;

    public void configure(Map<String, ?> configs) {
        try{
            sslAuthenticationContextValidatorClass = Class.forName(configs.get(KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp()).toString());

            if(null != sslAuthenticationContextValidatorClass) {
                LOGGER.info("Ssl Authentication Context Validator class is {}", KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp());

                sslAuthenticationContextValidator = (SslAuthenticationContextValidator) Utils.newInstance(sslAuthenticationContextValidatorClass);

                if (null != sslAuthenticationContextValidator) {
                    sslAuthenticationContextValidator.configure(configs);
                }
                else {
                    LOGGER.error("Class {} provider by {} cannot be found or initialized. {}", sslAuthenticationContextValidatorClass, KafkaConfig.AzpubsubSslAuthenticationValidatorClassDoc(), KafkaConfig.AzpubsubSslAuthenticationValidatorClassDoc());

                    throw new IllegalArgumentException("Class " + sslAuthenticationContextValidatorClass + " provided by setting " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp()  + " is not found or cannot be initialized. " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassDoc());
                }
            }

            saslAuthenticationContextValidatorClass = Class.forName(configs.get(KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp()).toString());

            if (null != saslAuthenticationContextValidatorClass) {

                saslAuthenticationContextValidator = (SaslAuthenticationContextValidator) Utils.newInstance(saslAuthenticationContextValidatorClass);

                if(null != saslAuthenticationContextValidator) {
                    saslAuthenticationContextValidator.configure(configs);
                }
                else {
                    LOGGER.error("Class {} provided by setting {} cannot be found or initialized. {}", saslAuthenticationContextValidatorClass, KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp(), KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());

                    throw new IllegalArgumentException("Class " + saslAuthenticationContextValidatorClass + " provided by setting " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp() + " is not found. " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());
                }
            }
        }
        catch(ClassNotFoundException ex) {
           throw new IllegalArgumentException(ex.getClass() + ". Error Message: " + ex.getMessage());
        }
    }

    public KafkaPrincipal build(AuthenticationContext context) {

        if ( context instanceof PlaintextAuthenticationContext ) {

            return KafkaPrincipal.ANONYMOUS;
        }
        else if ( context instanceof SslAuthenticationContext ) {

            SslAuthenticationContext sslAuthenticationContext = (SslAuthenticationContext)context;

            if ( null != sslAuthenticationContextValidator ) {

                AzPubSubPrincipal azPubSubPrincipal = sslAuthenticationContextValidator.authenticate(sslAuthenticationContext.session());

                if(null == azPubSubPrincipal) {
                    throw new IllegalStateException("Ssl Authentication Context Validator failed to validate the current SSL session. the AzPubSub returned is null.");
                }

                return  new KafkaPrincipal(azPubSubPrincipal.getPrincipalType(), azPubSubPrincipal.getPrincipalName());
            }

            if( null == sslAuthenticationContextValidatorClass) {
                LOGGER.error("No class is provided by {}", KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp());

                throw new IllegalArgumentException("No class name is provided by setting " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp() + " or class path is invalid. " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassDoc());
            }
            else {
                LOGGER.error("Class {} provider by {} cannot be found or initialized", sslAuthenticationContextValidatorClass, KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp());

                throw new IllegalArgumentException("Class " + sslAuthenticationContextValidatorClass + " provided by setting " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassProp() + " is not found or cannot be initialized. " + KafkaConfig.AzpubsubSslAuthenticationValidatorClassDoc());
            }
        }
        else if ( context instanceof SaslAuthenticationContext ) {

            SaslServer saslServer = ((SaslAuthenticationContext) context).server();

            if (null != saslAuthenticationContextValidator ) {

                AzPubSubPrincipal azPubSubPrincipal = saslAuthenticationContextValidator.authenticate(saslServer);

                if(null == azPubSubPrincipal) {
                    throw new IllegalSaslStateException("Sasl Authentication Context Validator failed to authenticate the current context, the AzPubSub principal return is null.");
                }

                return new KafkaPrincipal(azPubSubPrincipal.getPrincipalType(), azPubSubPrincipal.getPrincipalName());
            }

            if( null == saslAuthenticationContextValidatorClass) {

                LOGGER.error("No class name provided by setting {}, or class path is invalid. {}", KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp(), KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());

                throw new IllegalArgumentException("No class name is provided by setting " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp() + " or class path is invalid. " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());
            }
            else {

                LOGGER.error("Class {} provided by setting {} cannot be found or initialized. {}", saslAuthenticationContextValidatorClass, KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp(), KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());

                throw new IllegalArgumentException("Class " + saslAuthenticationContextValidatorClass + " provided by setting " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassProp() + " is not found. " + KafkaConfig.AzPubSubSaslAuthenticationValidatorClassDoc());
            }
        }
        else {
            throw new IllegalArgumentException("Unhandled authentication context type: " + context.getClass().getName());
        }
    }
}