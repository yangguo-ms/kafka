/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.kafka.common.security.saml;

import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

// import jdk.nashorn.internal.parser.JSONParser;
import org.apache.kafka.common.errors.SaslAuthenticationException;
import org.apache.kafka.common.security.JaasContext;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.common.security.authenticator.SaslServerCallbackHandler;
import org.apache.kafka.common.security.saml.DstsMetadata;
import org.apache.kafka.common.security.saml.Token;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import net.sf.jni4net.Bridge;
import dstsauthentication.DstsAuthentication;
import dstsauthentication.AuthenticationResult;
import com.microsoft.autopilot.ApRuntime;
import com.microsoft.autopilot.Configuration;
import com.google.gson.Gson;

/**
 * Simple SaslServer implementation for SASL/PLAIN. In order to make this implementation
 * fully pluggable, authentication of username/password is fully contained within the
 * server implementation.
 * <p>
 * Valid users with passwords are specified in the Jaas configuration file. Each user
 * is specified with user_<username> as key and <password> as value. This is consistent
 * with Zookeeper Digest-MD5 implementation.
 * <p>
 * To avoid storing clear passwords on disk or to integrate with external authentication
 * servers in production systems, this module can be replaced with a different implementation.
 *
 */
public class SamlSaslServer implements SaslServer {
    private static final Logger log = LoggerFactory.getLogger(SamlSaslServer.class);

    public static final String PLAIN_MECHANISM = "PLAIN";
    public static final String LIB_PATH = "../../libs";
    public static final String DSTS_SECTION_NAME = "Dsts";
    public static final String DSTS_CONFIG_SERVICEDNSNAME="ServiceDnsName";
    public static final String DSTS_CONFIG_SERVICENAME="ServiceName";
    public static final String DSTS_CONFIG_DSTSREALM="DstsRealm";
    public static final String DSTS_CONFIG_DSTSDNSNAME="DstsDns";
    public static final String DSTS_CONFIG_ROLE="Role";
    public static final String DSTS_METADATA_CONFIGFILE="dsts.metadata.configfile";
    public static final String DSTS_AUTHENTICATION_J4N_LIBRARY = "dsts.authenticationJ4nLibrary";
    public static final String AUTHENTICATION_STATUS_OK="OK";
    public static final String PRINCIPAL_TYPE = "principal.type";

    private final JaasContext jaasContext;
    private final Map<String, ?> props;
    private final Map<String, String> customizedProperties = new HashMap<>();


    private boolean complete;
    private String authorizationId;
    private DstsMetadata dstsMetadata = null;
    private Configuration configuration = null;


    public SamlSaslServer(JaasContext jaasContext, Map<String, ?> props) {
        this.jaasContext = jaasContext;
        this.props = props;

        log.info("creating Plain Sasl Server ......");
        if(!ApRuntime.isInitialized()){
            log.info("Initializing AP Runtime ...");
            ApRuntime.initialize();
        }
        try{
            log.info("getting config file path");
            String dataDir = ApRuntime.GetDataDir();
            String configFilePath = dataDir + "\\AzPubSubConfig\\" + System.getProperty(DSTS_METADATA_CONFIGFILE);
            configFilePath = configFilePath.replace('\\', '/');

            log.info("Dsts metadata configFilePath: {}", configFilePath);

            configuration = new Configuration(configFilePath);

            String dstsDns = configuration.getStringParameter(DSTS_SECTION_NAME, DSTS_CONFIG_DSTSDNSNAME, "");
            String serviceDnsName = configuration.getStringParameter(DSTS_SECTION_NAME, DSTS_CONFIG_SERVICEDNSNAME, "");
            String serviceName = configuration.getStringParameter(DSTS_SECTION_NAME, DSTS_CONFIG_SERVICENAME, "");
            String dstsRealm = configuration.getStringParameter(DSTS_SECTION_NAME, DSTS_CONFIG_DSTSREALM, "");
            String claimRole = configuration.getStringParameter(DSTS_SECTION_NAME, DSTS_CONFIG_ROLE, "");
            log.info("DstsDnsName: {}, ServiceDnsName: {}, ServiceName: {}, Realm: {}", dstsDns, serviceDnsName, serviceName, dstsRealm);
            dstsMetadata = new DstsMetadata(dstsDns, serviceDnsName, serviceName, dstsRealm, claimRole);
            log.info("Dsts Dns Name: {}", dstsMetadata.DstsDns);
            log.info("Dsts Service Name: {}", dstsMetadata.ServiceName);
            log.info("Dsts Service Dns Name: {}", dstsMetadata.ServiceDnsName);
            log.info("Dsts Service Dsts Realm: {}", dstsMetadata.DstsRealm);
        }
        catch(Exception e){
            log.error("Exception caught: {}", e.getMessage());
        }
    }

    /**
     * @throws SaslAuthenticationException if username/password combination is invalid or if the requested
     *         authorization id is not the same as username.
     * <p>
     * <b>Note:</b> This method may throw {@link SaslAuthenticationException} to provide custom error messages
     * to clients. But care should be taken to avoid including any information in the exception message that
     * should not be leaked to unauthenticated clients. It may be safer to throw {@link SaslException} in
     * some cases so that a standard error message is returned to clients.
     * </p>
     */
    @Override
    public byte[] evaluateResponse(byte[] response) throws SaslException, SaslAuthenticationException {
        /*
         * Message format (from https://tools.ietf.org/html/rfc4616):
         *
         * message   = [authzid] UTF8NUL authcid UTF8NUL passwd
         * authcid   = 1*SAFE ; MUST accept up to 255 octets
         * authzid   = 1*SAFE ; MUST accept up to 255 octets
         * passwd    = 1*SAFE ; MUST accept up to 255 octets
         * UTF8NUL   = %x00 ; UTF-8 encoded NUL character
         *
         * SAFE      = UTF1 / UTF2 / UTF3 / UTF4
         *                ;; any UTF-8 encoded Unicode character except NUL
         */

        log.info("starting authentication ....");
        String[] tokens;
        try {
            tokens = new String(response, "UTF-8").split("\u0000");
        } catch (UnsupportedEncodingException e) {
            throw new SaslException("UTF-8 encoding not supported", e);
        }
        if (tokens.length != 3)
            throw new SaslException("Invalid SASL/PLAIN response: expected 3 tokens, got " + tokens.length);
        String username = tokens[1];
        String password = tokens[2];
        log.info("token: {}", password);

        if (username.isEmpty()) {
            throw new SaslException("Authentication failed: username not specified");
        }
        if (password.isEmpty()) {
            throw new SaslException("Authentication failed: password not specified");
        }

        String j4nLibFilePath = LIB_PATH + "/" + System.getProperty(DSTS_AUTHENTICATION_J4N_LIBRARY);
        String dstsMetadataJson;

        try {
            Bridge.init(new File(LIB_PATH));
            Bridge.LoadAndRegisterAssemblyFrom(new java.io.File(j4nLibFilePath));
            DstsAuthentication authentication = new DstsAuthentication();

            AuthenticationResult res = authentication.Authenticate(dstsMetadata.DstsRealm,
                    dstsMetadata.DstsDns,
                    dstsMetadata.ServiceDnsName,
                    dstsMetadata.ServiceName,
                    password);

            String status = res.getStatus();
            String errorMessage = res.getErrorMessage();

            if(status.equals(AUTHENTICATION_STATUS_OK)) {
                Gson gson = new Gson();
                Token token = new Token(res.getClaims(), res.getValidFrom(), res.getValidTo());
                this.authorizationId = gson.toJson(token);
                this.customizedProperties.put(this.PRINCIPAL_TYPE, KafkaPrincipal.Token_Type);

                if(this.authorizationId != null && !this.authorizationId.isEmpty()){
                    complete = true;
                    return new byte[0];
                }
            }
            log.error("Failed to authenticate token for user: {}, status: {}, error message: {}", username, status, errorMessage);
            throw new SaslAuthenticationException(log.toString());
        }
        catch(FileNotFoundException e) {
            log.error("Authentication J4n Assembly cannot be found under folder: {}, error message: {}, cause: {}", LIB_PATH, e.getMessage(), null == e.getCause()? "Unknown cause." :  e.getCause().getMessage());
            throw new SaslException(log.toString());
        }
        catch(IOException e){
            log.error("IOException happened. Error message: {}", e.getMessage());
            throw new SaslException(log.toString());
        }
        catch(UnsupportedClassVersionError e) {
            log.error("Class Version not supported error: {}", e.getMessage());
            throw new SaslException(log.toString());
        }
        catch(UnsatisfiedLinkError e) {
            log.error("JNI error: unsatisfied link error: {}", e.getMessage());
            throw new SaslException(log.toString());
        }
    }

    @Override
    public String getAuthorizationID() {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return authorizationId;
    }

    @Override
    public String getMechanismName() {
        return PLAIN_MECHANISM;
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        if(this.customizedProperties.containsKey(propName)){
            return this.customizedProperties.get(propName);
        }
        return null;
    }

    @Override
    public boolean isComplete() {
        return complete;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(incoming, offset, offset + len);
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
        if (!complete)
            throw new IllegalStateException("Authentication exchange has not completed");
        return Arrays.copyOfRange(outgoing, offset, offset + len);
    }

    @Override
    public void dispose() throws SaslException {
    }

    public static class SamlSaslServerFactory implements SaslServerFactory {
        private static final Logger log = LoggerFactory.getLogger(SamlSaslServerFactory.class);

        @Override
        public SaslServer createSaslServer(String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh)
                throws SaslException {

            log.info("creating Sasl Server ...");

            if (!PLAIN_MECHANISM.equals(mechanism))
                throw new SaslException(String.format("Mechanism \'%s\' is not supported. Only PLAIN is supported.", mechanism));

            if (!(cbh instanceof SaslServerCallbackHandler))
                throw new SaslException("CallbackHandler must be of type SaslServerCallbackHandler, but it is: " + cbh.getClass());

            return new SamlSaslServer(((SaslServerCallbackHandler) cbh).jaasContext(), props);
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            if (props == null) return new String[]{PLAIN_MECHANISM};
            String noPlainText = (String) props.get(Sasl.POLICY_NOPLAINTEXT);
            if ("true".equals(noPlainText))
                return new String[]{};
            else
                return new String[]{PLAIN_MECHANISM};
        }
    }
}
