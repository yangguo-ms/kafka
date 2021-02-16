package com.microsoft.azpubsub.security.auth

import com.typesafe.scalalogging.Logger
import com.yammer.metrics.core.{Meter, MetricName}
import kafka.metrics.KafkaMetricsGroup
import kafka.security.auth.Topic
import kafka.security.authorizer.{AclAuthorizer, AuthorizerUtils}
import kafka.utils.Logging
import org.apache.kafka.common.security.auth.{KafkaPrincipal, SecurityProtocol}
import org.apache.kafka.common.utils.Utils
import org.apache.kafka.server.authorizer.{Action, AuthorizableRequestContext, AuthorizationResult}

import java.net.InetAddress
import java.util
import java.util.concurrent._
import scala.collection.JavaConverters.{asScalaSetConverter, _}
import scala.util.control.Breaks

/*
 * AzPubSub ACL Authorizer to handle the certificate & role based principal type
 */
class AzPubSubAclAuthorizer extends AclAuthorizer with Logging with KafkaMetricsGroup {
  private[security] val aclAuthorizerLogger = Logger("kafka.authorizer.logger")

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

//  def authorize(session: Session, operation: Operation, resource: Resource): Boolean = {
//    if (resource.resourceType == Topic && authZConfig.isDisabled(resource.name)) {
//      aclAuthorizerLogger.debug(s"AuthZ is disabled for resource: $resource")
//      successRate.mark()
//      disabledRate.mark()
//      return true
//    }
//
//    var requestContext = AuthorizerUtils.sessionToRequestContext(session)
//    val action = new Action(operation.toJava, resource.toPattern, 1, true, true)
//    val sessionPrincipal = session.principal
//    if (classOf[AzPubSubPrincipal] == sessionPrincipal.getClass) {
//      val principal = sessionPrincipal.asInstanceOf[AzPubSubPrincipal]
//      for (role <- principal.getRoles.asScala) {
//        val claimPrincipal = new KafkaPrincipal(principal.getPrincipalType(), role)
//        val claimSession = new Session(claimPrincipal, session.clientAddress)
//        requestContext = AuthorizerUtils.sessionToRequestContext(claimSession)
//        if (super.authorize(requestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
//          successRate.mark()
//          return true
//        }
//      }
//    } else if (super.authorize(requestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
//      successRate.mark()
//      return true
//    }
//
//    failureRate.mark()
//    return false
//  }

  override def authorize(requestContext: AuthorizableRequestContext, actions: util.List[Action]): util.List[AuthorizationResult] = {
    var authorizationResults = List[AuthorizationResult]()
    val loop = new Breaks
    for (action <- actions.asScala) {
      val resource = AuthorizerUtils.convertToResource(action.resourcePattern)
      if (resource.resourceType == Topic && authZConfig.isDisabled(resource.name)) {
        aclAuthorizerLogger.debug(s"AuthZ is disabled for resource: $resource")
        successRate.mark()
        disabledRate.mark()
        authorizationResults ::= AuthorizationResult.ALLOWED
      } else if (classOf[AzPubSubPrincipal] == requestContext.principal.getClass) {
        val principal = requestContext.principal.asInstanceOf[AzPubSubPrincipal]
        loop.breakable {
          for (role <- principal.getRoles.asScala) {
            val claimPrincipal = new KafkaPrincipal(principal.getPrincipalType(), role)
            val claimRequestContext = getClaimRequestContext(requestContext, claimPrincipal)
            if (super.authorize(claimRequestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
              successRate.mark()
              authorizationResults ::= AuthorizationResult.ALLOWED
              loop.break
            }
          }
        }
      } else if (super.authorize(requestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
          successRate.mark()
          authorizationResults ::= AuthorizationResult.ALLOWED
      } else {
        failureRate.mark()
        authorizationResults ::= AuthorizationResult.DENIED
      }
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

    return authorizationResults.asJava
  }
}
