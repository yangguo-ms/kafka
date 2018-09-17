package com.microsoft.autopilot.azpubsub;

import java.security.Provider;

public final class APPKIProvider extends Provider{

	private final static String ALGORITHM = "APPKI";
    private final static Double VERSION = 1.0;
    private final static String INFO = "Azure AP PKI infrastructure";
    private final static String KEY_MGR_SPI = "com.microsoft.autopilot.azpubsub.APPKIKeyManagerFactorySpi";
    private final static String TRUST_MGR_SPI = "com.microsoft.autopilot.azpubsub.APPKITrustManagerFactorySpi";
	private final static String KEY_MGR_APPKI = "KeyManagerFactory.APPKI";
	private final static String TRUST_MGR_APPKI = "TrustManagerFactory.APPKI";

	private static final long serialVersionUID = 1L;

	public APPKIProvider()
    {
		super(ALGORITHM, VERSION, INFO);
        put(KEY_MGR_APPKI, KEY_MGR_SPI);
        put(TRUST_MGR_APPKI, TRUST_MGR_SPI);
    }   
}
