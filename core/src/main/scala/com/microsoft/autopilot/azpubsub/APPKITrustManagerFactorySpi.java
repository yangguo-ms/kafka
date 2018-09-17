package com.microsoft.autopilot.azpubsub;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;

import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.TrustManagerFactorySpi;

/**
 * The factory for the APPKITrustManager
 **/
public final class APPKITrustManagerFactorySpi extends TrustManagerFactorySpi
{
  protected final String algorithm = "APPKI";
  protected TrustManagerFactory factory;
  public APPKITrustManagerFactorySpi () { }

  protected void engineInit (ManagerFactoryParameters mgrparams)
  {
	  
  }

  protected void engineInit (KeyStore keystore) throws KeyStoreException
  {

  try {
		factory = TrustManagerFactory.getInstance(algorithm);
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}
  }

  /**
   * Returns a collection of trust managers that are naive. 
   * This collection is just a single element array containing
   * our {@link APPKITrustManager} class.
   **/
  protected TrustManager[] engineGetTrustManagers ()
  {
    return new TrustManager[] { new APPKITrustManager() } ;
  }

  /**
   * Returns our "NaiveTrustAlgorithm" string.
   * @return The string, "NaiveTrustAlgorithm"
   */
  public static String getAlgorithm()
  {
    return "APPKI";
  }

}