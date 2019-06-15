package azpubsub.kafka.security.auth

import java.util.Map

trait TokenValidator {
  def configure(javaConfigs: Map[String, _]): Unit
  def validate(base64TokenString: String) : Boolean
}
