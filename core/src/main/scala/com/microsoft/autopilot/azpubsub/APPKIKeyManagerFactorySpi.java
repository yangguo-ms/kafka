package com.microsoft.autopilot.azpubsub;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

/**
 * APPKIKeyManagerFactorySpi is used by Java's KeyManagerFactory to create the KeyManmager instances. This class
 * contains the initialization of the KeyManager based on the base algorithm.
 */
public class APPKIKeyManagerFactorySpi extends KeyManagerFactorySpi {
    protected final String algorithm = "APPKI";
    protected String baseAlgorithm;
    private APPKIKeyManager keyManager = null;
    KeyManagerFactory kmf = null;
    
    /**
     * Initializes the KeyManagerFactory with the keystore and its password. This class creates an instance of the
     * KeyManagerFactory created using the base algorithm / default algorithm and determines the key alias which should
     * be used.
     *
     * @param keyStore Keystore containing the private key
     * @param chars Password to access the keyStore
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    protected void engineInit(KeyStore keyStore, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        keyManager = new APPKIKeyManager(keyStore);
    }

    /**
     * Currently not implemented.
     *
     * @param managerFactoryParameters ManagerFactoryParameters object containing the parametrs of the KeyManagerFactory.
     * @throws InvalidAlgorithmParameterException
     */
    protected void engineInit(ManagerFactoryParameters managerFactoryParameters) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Unsupported ManagerFactoryParameters");
    }

	@Override
	protected KeyManager[] engineGetKeyManagers() {
		return new KeyManager[] { this.keyManager.getKeyManager()};
	}
    
}