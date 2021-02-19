package com.microsoft.azpubsub.security.auth

import com.yammer.metrics.core.{Meter, MetricName}
import kafka.metrics.KafkaMetricsGroup
import kafka.security.auth._
import kafka.security.authorizer.{AclAuthorizer, AuthorizerUtils}
import kafka.utils.Logging
import org.apache.kafka.common.security.auth.{KafkaPrincipal, SecurityProtocol}
import org.apache.kafka.common.utils.Utils
import org.apache.kafka.server.authorizer.{Action, AuthorizableRequestContext, AuthorizationResult}

import java.net.InetAddress
import java.util
import java.util.concurrent._
import java.util.regex.Pattern
import scala.collection.JavaConverters.asScalaSetConverter

/*
 * AzPubSub ACL Authorizer to handle the certificate & role based principal type
 */
class AzPubSubAclAuthorizer extends AclAuthorizer with Logging with KafkaMetricsGroup {

  private val successRate: Meter = newMeter("AuthorizerSuccessPerSec", "success", TimeUnit.SECONDS)
  private val failureRate: Meter = newMeter("AuthorizerFailurePerSec", "failure", TimeUnit.SECONDS)
  private val disabledRate: Meter = newMeter("AuthorizerDisabledPerSec", "success", TimeUnit.SECONDS)

  private var authZConfig: AuthZConfig = null

  override def configure(javaConfigs: util.Map[String, _]): Unit = {
    val config = AzPubSubConfig.fromProps(javaConfigs)
    authZConfig = Utils.newInstance(config.getString(AzPubSubConfig.AUTHZ_CLASS_CONFIG), classOf[AuthZConfig])
    authZConfig.configure()
    super.configure(javaConfigs)
  }

  override def metricName(name: String, metricTags: scala.collection.Map[String, String]): MetricName = {
    explicitMetricName("azpubsub.security", "AuthorizerMetrics", name, metricTags)
  }

  override def authorizeAction(requestContext: AuthorizableRequestContext, action: Action): AuthorizationResult = {
    val resource = AuthorizerUtils.convertToResource(action.resourcePattern)
    if (resource.resourceType == Topic && authZConfig.isDisabled(resource.name)) {
      authorizerLogger.debug(s"AuthZ is disabled for resource: $resource")
      successRate.mark()
      disabledRate.mark()
      return AuthorizationResult.ALLOWED
    }

    def getClaimRequestContext(requestContext: AuthorizableRequestContext, claimPrincipal: KafkaPrincipal): AuthorizableRequestContext = {
      new AuthorizableRequestContext {
        override def clientId(): String = requestContext.clientId
        override def requestType(): Int = requestContext.requestType
        override def listenerName(): String = requestContext.listenerName
        override def clientAddress(): InetAddress = requestContext.clientAddress
        override def principal(): KafkaPrincipal = claimPrincipal
        override def securityProtocol(): SecurityProtocol = requestContext.securityProtocol
        override def correlationId(): Int = requestContext.correlationId
        override def requestVersion(): Int = requestContext.requestVersion
      }
    }

    val sessionPrincipal = requestContext.principal
    if (classOf[AzPubSubPrincipal] == sessionPrincipal.getClass) {
      val principal = sessionPrincipal.asInstanceOf[AzPubSubPrincipal]
      for (role <- principal.getRoles.asScala) {
        val claimPrincipal = new KafkaPrincipal(principal.getPrincipalType(), role)
        val claimRequestContext = getClaimRequestContext(requestContext, claimPrincipal)
        if (super.authorizeAction(claimRequestContext, action) == AuthorizationResult.ALLOWED) {
          successRate.mark()
          return AuthorizationResult.ALLOWED
        }
      }
    } else if (super.authorizeAction(requestContext, action) == AuthorizationResult.ALLOWED) {
      successRate.mark()
      return AuthorizationResult.ALLOWED
    }

    failureRate.mark()
    return AuthorizationResult.DENIED
  }

  override def matchingAclExists(operation: Operation, resource: Resource, principal: KafkaPrincipal, host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {
    acls.find { acl =>
      acl.permissionType == permissionType &&
              acl.principal.matching(principal) &&
              (operation == acl.operation || acl.operation == All) &&
              (acl.host == host || acl.host == Acl.WildCardHost)
    }.exists { acl =>
      authorizerLogger.debug(s"operation = $operation on resource = $resource from host = $host is $permissionType based on acl = $acl")
      true
    }
  }
}
