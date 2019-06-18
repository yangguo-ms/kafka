import java.util

import azpubsub.kafka.security.auth.TokenValidator

class mockTokenValidator extends TokenValidator{
  override def configure(javaConfigs: util.Map[String, _]): Unit = {

  }

  override def validate(base64TokenString: String): Boolean = true
}
