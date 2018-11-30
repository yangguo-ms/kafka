package kafka.security.auth

import java.util

import com.typesafe.scalalogging.Logger
import kafka.network.RequestChannel
import kafka.utils.Logging
import org.apache.kafka.common.security.auth.KafkaPrincipal

class AnotherSimpleAclAuthorizer extends Authorizer with Logging{

  private val authorizerLogger = Logger("kafka.authorizer.logger")
  override def authorize(session: RequestChannel.Session, operation: Operation, resource: Resource): Boolean = {
    true
  }

  override def configure(configs: util.Map[String, _]): Unit = {}

  override def close(): Unit = {}

  override def addAcls(acls: Set[Acl], resource: Resource): Unit = {}

  override def getAcls(): Map[Resource, Set[Acl]] = null

  override def getAcls(principal: KafkaPrincipal): Map[Resource, Set[Acl]] = null

  override def getAcls(resource: Resource): Set[Acl] = null

  override def removeAcls(acls: Set[Acl], resource: Resource): Boolean = false

  override def removeAcls(resource: Resource): Boolean = false
}
