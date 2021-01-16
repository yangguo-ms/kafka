package com.microsoft.azpubsub.security.auth

import java.util
import java.util.concurrent._

import scala.collection.JavaConverters.asScalaSetConverter

import com.typesafe.scalalogging.Logger
import com.yammer.metrics.core.{Meter, MetricName}

import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.common.utils.Utils

import kafka.metrics.KafkaMetricsGroup
import kafka.network.RequestChannel.Session
import kafka.security.auth.Operation
import kafka.security.auth.{Resource, Topic}
import kafka.security.auth.SimpleAclAuthorizer
import kafka.utils.Logging

/*
 * AzPubSub ACL Authorizer to handle the certificate & role based principal type
 */
class AzPubSubAclAuthorizer extends SimpleAclAuthorizer with Logging with KafkaMetricsGroup {
  private[security] val authorizerLogger = Logger("kafka.authorizer.logger")

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

  override def authorize(session: Session, operation: Operation, resource: Resource): Boolean = {
    if (resource.resourceType == Topic && authZConfig.isDisabled(resource.name)) {
      authorizerLogger.debug(s"AuthZ is disabled for resource: $resource")
      successRate.mark()
      disabledRate.mark()
      return true
    }

    val sessionPrincipal = session.principal
    if (classOf[AzPubSubPrincipal] == sessionPrincipal.getClass) {
      val principal = sessionPrincipal.asInstanceOf[AzPubSubPrincipal]
      for (role <- principal.getRoles.asScala) {
        val claimPrincipal = new KafkaPrincipal(principal.getPrincipalType(), role)
        val claimSession = new Session(claimPrincipal, session.clientAddress)
        if (super.authorize(claimSession, operation, resource)) {
          successRate.mark()
          return true
        }
      }
    } else if (super.authorize(session, operation, resource)) {
      successRate.mark()
      return true
    }

    failureRate.mark()
    return false
  }
}
