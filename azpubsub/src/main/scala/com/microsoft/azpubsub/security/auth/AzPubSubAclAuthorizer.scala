package com.microsoft.azpubsub.security.auth

import com.typesafe.scalalogging.Logger
import com.yammer.metrics.core.{Meter, MetricName}
import kafka.metrics.KafkaMetricsGroup
import kafka.security.authorizer.AclAuthorizer
import kafka.utils.{Logging, Pool}
import org.apache.kafka.common.resource.ResourceType.TOPIC
import org.apache.kafka.common.security.auth.{KafkaPrincipal, SecurityProtocol}
import org.apache.kafka.common.utils.Utils
import org.apache.kafka.server.authorizer.{Action, AuthorizableRequestContext, AuthorizationResult}

import java.net.InetAddress
import java.util
import java.util.concurrent._
import scala.jdk.CollectionConverters._

/*
 * AzPubSub ACL Authorizer to handle the certificate & role based principal type
 */
class AzPubSubAclAuthorizer extends AclAuthorizer with Logging with KafkaMetricsGroup {
  private[security] val aclAuthorizerLogger = Logger("kafka.authorizer.logger")

  private val authorizerStats = new AuthorizerStats

  private var authZConfig: AuthZConfig = null

  override def configure(javaConfigs: util.Map[String, _]): Unit = {
    val config = AzPubSubConfig.fromProps(javaConfigs)
    authZConfig = Utils.newInstance(config.getString(AzPubSubConfig.AUTHZ_CLASS_CONFIG), classOf[AuthZConfig])
    authZConfig.configure()
    super.configure(javaConfigs)
  }

  override def authorize(requestContext: AuthorizableRequestContext, actions: util.List[Action]): util.List[AuthorizationResult] = {
    actions.asScala.map { action => this.authorizeAction(requestContext, action) }.asJava
  }

  private def authorizeAction(requestContext: AuthorizableRequestContext, action: Action): AuthorizationResult = {
    val resource = action.resourcePattern
    if (resource.resourceType == TOPIC && authZConfig.isDisabled(resource.name)) {
      aclAuthorizerLogger.debug(s"AuthZ is disabled for resource: $resource")
      authorizerStats.topicStats(resource.name).successRate.mark()
      authorizerStats.allTopicsStats.successRate.mark()
      authorizerStats.topicStats(resource.name).disabledRate.mark()
      authorizerStats.allTopicsStats.disabledRate.mark()
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
        if (super.authorize(claimRequestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
          authorizerStats.topicStats(resource.name).successRate.mark()
          authorizerStats.allTopicsStats.successRate.mark()
          return AuthorizationResult.ALLOWED
        }
      }
    } else if (super.authorize(requestContext, List(action).asJava).asScala.head == AuthorizationResult.ALLOWED) {
      authorizerStats.topicStats(resource.name).successRate.mark()
      authorizerStats.allTopicsStats.successRate.mark()
      return AuthorizationResult.ALLOWED
    }

    authorizerStats.topicStats(resource.name).failureRate.mark()
    authorizerStats.allTopicsStats.failureRate.mark()
    return AuthorizationResult.DENIED
  }
}

class AuthorizerMetrics(name: Option[String]) extends KafkaMetricsGroup {
  val tags: scala.collection.Map[String, String] = name match {
    case None => Map.empty
    case Some(topic) => Map("topic" -> topic)
  }

  case class MeterWrapper(metricType: String, eventType: String) {
    @volatile private var lazyMeter: Meter = _
    private val meterLock = new Object

    def meter(): Meter = {
      var meter = lazyMeter
      if (meter == null) {
        meterLock synchronized {
          meter = lazyMeter
          if (meter == null) {
            meter = newMeter(metricType, eventType, TimeUnit.SECONDS, tags)
            lazyMeter = meter
          }
        }
      }
      meter
    }

    if (tags.isEmpty) // greedily initialize the general topic metrics
      meter()
  }

  // an internal map for "lazy initialization" of certain metrics
  private val metricTypeMap = new Pool[String, MeterWrapper]()
  metricTypeMap.putAll(Map(
    AuthorizerStats.SuccessPerSec -> MeterWrapper(AuthorizerStats.SuccessPerSec, "success"),
    AuthorizerStats.FailurePerSec -> MeterWrapper(AuthorizerStats.FailurePerSec, "failure"),
    AuthorizerStats.DisabledPerSec -> MeterWrapper(AuthorizerStats.DisabledPerSec, "success"),
  ).asJava)

  def successRate = metricTypeMap.get(AuthorizerStats.SuccessPerSec).meter()

  def failureRate = metricTypeMap.get(AuthorizerStats.FailurePerSec).meter()

  def disabledRate = metricTypeMap.get(AuthorizerStats.DisabledPerSec).meter()

  override def metricName(name: String, metricTags: scala.collection.Map[String, String]): MetricName = {
    explicitMetricName("azpubsub.security", "AuthorizerMetrics", name, metricTags)
  }
}

object AuthorizerStats {
  val SuccessPerSec = "AuthorizerSuccessPerSec"
  val FailurePerSec = "AuthorizerFailurePerSec"
  val DisabledPerSec = "AuthorizerDisabledPerSec"

  private val valueFactory = (k: String) => new AuthorizerMetrics(Some(k))
}

class AuthorizerStats {
  import AuthorizerStats._

  private val stats = new Pool[String, AuthorizerMetrics](Some(valueFactory))
  val allTopicsStats = new AuthorizerMetrics(None)

  def topicStats(topic: String): AuthorizerMetrics = stats.getAndMaybePut(topic)
}