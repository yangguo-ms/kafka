package com.microsoft.autopilot.azpubsub;

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.microsoft.autopilot.ApPki;
import com.microsoft.autopilot.ApPki.ApAuthType;

/**
 * An X509KeyManager backed by Azure AP PKI infrastructure.
 */
public class APPKIKeyManager extends X509ExtendedKeyManager {
    private static final Logger LOG
            = LoggerFactory.getLogger(APPKIKeyManager.class);
    
    private ApAuthType authType;
    private X509KeyManager keyManager;
    private KeyStore keyStore;

    /**
     * Initialize the APPKIKeyManager in client mode.
     */
    public APPKIKeyManager(KeyStore keyStore) {
    	this(ApPki.ApAuthType.CLIENT, keyStore);
    	keyManager = getKeyManager();
    }

    /**
     * Initialize the APPKIKeyManager according to the specified authType.
     * @param authType Type of certificate to load
     */
    public APPKIKeyManager(ApAuthType authType, KeyStore keyStore) {
        this.authType = authType;

        if (keyStore != null) {
            this.keyStore = keyStore;
			X509Certificate localCert = ApPki.cachedApLookupLocalCert(authType);
            installCertToUserStore(localCert, keyStore);
        }
    }

    private static String installCertToUserStore(X509Certificate cert,
                                                 KeyStore keyStore) {
        KeyStore.ProtectionParameter protParam
                = new KeyStore.PasswordProtection(new char[0]);
        PrivateKey privateKey = ApPki.exportPrivateKey(cert);
        KeyStore.PrivateKeyEntry entry
                = new KeyStore.PrivateKeyEntry(privateKey,
                        new X509Certificate[] { cert });
        String alias = cert.getSubjectX500Principal().getName();
        try {
            keyStore.setEntry(alias, entry, protParam);
            LOG.debug("Installed certificate with alias {} to KeyStore", alias);
        } catch (KeyStoreException e) {
            LOG.error("Failed to set KeyStore entry for alias: " + alias, e);
            return null;
        }

        return alias;
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        LOG.debug("Looking up local certificate alias for client...");
        return chooseApPkiAlias();
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        LOG.debug("Looking up local certificate alias for server...");
        return chooseApPkiAlias();
    }

    private String chooseApPkiAlias() {
        X509Certificate localCert = ApPki.cachedApLookupLocalCert(authType);
        if (localCert == null) {
            LOG.error("Failed to look up local certificate.");
            return null;
        }

        LOG.debug("Local AP PKI cert: " + localCert.getSubjectX500Principal().getName());
        String apPkiAlias = null;
        try {
            apPkiAlias = keyStore.getCertificateAlias(localCert);
            if (apPkiAlias != null) {
                X509Certificate userCert = (X509Certificate) keyStore.getCertificate(apPkiAlias);
                LOG.debug("Found installed cert with alias {}: {}", apPkiAlias, userCert);
                if (!localCert.equals(userCert)) {
                    LOG.error("Certificates do not match. Installed cert may be out of date.");
                    apPkiAlias = null;
                }
            }
        } catch (KeyStoreException e) {
            LOG.error("Failed to get certificate alias for " + localCert.toString(), e);
            apPkiAlias = null;
        }

        if (apPkiAlias == null) {
            LOG.warn("Could not match certificate {} with an installed cert. "
                    + "Attempting to reinstall certificate to Windows-MY.",
                    localCert.toString());
            apPkiAlias = installCertToUserStore(localCert, keyStore);

            // Reload key manager to pick up new certificate
            keyManager = getKeyManager();
        }

        LOG.debug("AP PKI alias = " + apPkiAlias);
        return apPkiAlias;
    }
    
    /**
     * Load an X509KeyManager backed by a KeyStore.
     * @param keyStore The store holding the local machine certificates.
     * @return An initialized X509KeyManager backed by the KeyStore.
     */
    protected X509KeyManager getKeyManager() {
        KeyManagerFactory kmf = null;
        try {
            kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, null);
            LOG.debug("Initialized KeyManagerFactory");
        } catch (NoSuchAlgorithmException e) {
            LOG.error("SunX509 is not a supported algorithm", e);
            return null;
        } catch (UnrecoverableKeyException e) {
            LOG.error("Error initializing SunX509 KeyManagerFactory", e);
            return null;
        } catch (KeyStoreException e) {
            LOG.error("Error initializing SunX509 KeyManagerFactory", e);
            return null;
        }

        KeyManager[] keyManagers = kmf.getKeyManagers();

        if (keyManagers.length == 0) {
            LOG.error("SunX509 KeyManagerFactory returned no KeyManagers");
            return null;
        }

        return (X509KeyManager) keyManagers[0];
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        LOG.debug("Getting certificate chain for alias {}", alias);
        return keyManager.getCertificateChain(alias);
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        LOG.debug("Getting client aliases...");
        return keyManager.getClientAliases(keyType, issuers);
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        LOG.debug("Getting private key for alias {}", alias);
        return keyManager.getPrivateKey(alias);
    }
    
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        LOG.debug("Getting server aliases...");
        return keyManager.getServerAliases(keyType, issuers);
    }
}
