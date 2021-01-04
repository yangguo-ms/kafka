package com.microsoft.azpubsub.security.auth;

/*
 * Interface retrieve the AuthZ Enable/Disable flag for Topic
 */
public interface AuthZConfig {
	public void configure() throws Exception;

	public boolean isDisabled(String topic);
}
