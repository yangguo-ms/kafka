package azpubsub.kafka.security.auth

import java.util.Map

/**
  * Interface to validate base64 encoded token from Kafka client.
  */
trait TokenValidator {
  /**
    * Interface to pass in configuration settings.
    * @param javaConfigs configuration settings
    */
  def configure(javaConfigs: Map[String, _]): Unit

  /**
    * validate token from client.
    * @param base64TokenString token encoded in base64
    * @return
    */
  def validate(base64TokenString: String) : Boolean

  /**
    * validate token from client, token is allowed to be exipired.
    * @param base64TokenString token encoded in base64
    * @return true - if token is valid or even the token is expired but it is not recalled;
    *         false - if token is invalid (siganture validation failed, etc.)
    */
  def validateWithTokenExpiredAllowed(base64TokenString: String) : Boolean
}
