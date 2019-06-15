/**
  * Licensed to the Apache Software Foundation (ASF) under one or more
  * contributor license agreements.  See the NOTICE file distributed with
  * this work for additional information regarding copyright ownership.
  * The ASF licenses this file to You under the Apache License, Version 2.0
  * (the "License"); you may not use this file except in compliance with
  * the License.  You may obtain a copy of the License at
  * <p/>
  * http://www.apache.org/licenses/LICENSE-2.0
  * <p/>
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */


package azpubsub.kafka.security.auth

import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.text.SimpleDateFormat
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantReadWriteLock
import java.util.{Date, Locale, TimeZone}

import azpubsub.kafka.security.auth.SimpleAclAuthorizer.VersionedAcls
import com.yammer.metrics.core.Gauge
import kafka.common.{NotificationHandler, ZkNodeChangeNotificationListener}
import kafka.metrics.KafkaMetricsGroup
import kafka.network.RequestChannel.Session
import kafka.security.auth.SimpleAclAuthorizer.VersionedAcls
import kafka.server.KafkaConfig
import kafka.utils.CoreUtils.{inReadLock, inWriteLock}
import kafka.utils.{CoreUtils, Json}
import kafka.zk.{AclChangeNotificationSequenceZNode, AclChangeNotificationZNode, KafkaZkClient}
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.common.utils.Time
import org.slf4j.LoggerFactory
import kafka.security.auth.TokenValidator

import scala.collection.JavaConverters._
import scala.collection.mutable
import scala.util.{Random, Try}

object  AzPubSubAclAuthorizer{
  val AzPubSubAclAuthorizingRequest = "AzPubSubAclAuthorizingRequest"
  val TokenDesearializationFailRateMs = "TokenDesearializationFailRateMs"
  val Saml2TokenTimeFormatter = "M/dd/yyyy hh:mm:ss a"
  val TokenInvalidFromDatetimeRateMs = "TokenInvalidFromDatetimeRateMs"
  val TokenExpiredRateMs = "TokenExpiredRateMs"
  val TopicAuthorizationUsingTokenSuccessfulRateMs = "TopicAuthorizationUsingTokenSuccessfulRateMs"
  val TokenNotAuthorizedForTopicRateMs = "TokenNotAuthorizedForTopicRateMs"
  val TokenValidatorClassPathKey = "token.validator.class"

  val ZkUrlProp = "authorizer.zookeeper.url"
  val ZkConnectionTimeOutProp = "authorizer.zookeeper.connection.timeout.ms"
  val ZkSessionTimeOutProp = "authorizer.zookeeper.session.timeout.ms"
  val ZkMaxInFlightRequests = "authorizer.zookeeper.max.in.flight.requests"
  val ValidateTokenInMinutes = "validate.token.in.minutes"

  case class VersionedAcls(acls: Set[Acl], zkVersion: Int)
}


class AzPubSubAclAuthorizer extends Authorizer with KafkaMetricsGroup {

  private val LOGGER = LoggerFactory.getLogger(classOf[AzPubSubAclAuthorizer])
  private var brokerHosts  = Set[String]()
  private var cacheTokenLastValidatedTime = new mutable.HashMap[String, Date];
  private var tokenAuthenticator : TokenValidator = null
  private var periodToValidateTokenInMinutes : Int = 60
  private var zkClient: KafkaZkClient = null
  private var aclChangeListener: ZkNodeChangeNotificationListener = null
  private val aclCache = new scala.collection.mutable.HashMap[Resource, VersionedAcls]
  private val lock = new ReentrantReadWriteLock()
  private val retryBackoffMs = 100
  private val retryBackoffJitterMs = 50

  protected[auth] var maxUpdateRetries = 10

  override def configure(javaConfigs: java.util.Map[String, _]): Unit = {
    val configs = javaConfigs.asScala
    val props = new java.util.Properties()
    configs.foreach { case (key, value) => props.put(key, value.toString) }

    tokenAuthenticator = CoreUtils.createObject[TokenValidator](configs.get(AzPubSubAclAuthorizer.TokenValidatorClassPathKey).get.toString)
    periodToValidateTokenInMinutes = configs.get(AzPubSubAclAuthorizer.ValidateTokenInMinutes).getOrElse("60").toString.toInt

    val kafkaConfig = KafkaConfig.fromProps(props, doLog = false)
    val zkUrl = configs.get(SimpleAclAuthorizer.ZkUrlProp).map(_.toString).getOrElse(kafkaConfig.zkConnect)
    val zkConnectionTimeoutMs = configs.get(SimpleAclAuthorizer.ZkConnectionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkConnectionTimeoutMs)
    val zkSessionTimeOutMs = configs.get(SimpleAclAuthorizer.ZkSessionTimeOutProp).map(_.toString.toInt).getOrElse(kafkaConfig.zkSessionTimeoutMs)
    val zkMaxInFlightRequests = configs.get(SimpleAclAuthorizer.ZkMaxInFlightRequests).map(_.toString.toInt).getOrElse(kafkaConfig.zkMaxInFlightRequests)

    val time = Time.SYSTEM
    zkClient = KafkaZkClient(zkUrl, kafkaConfig.zkEnableSecureAcls, zkSessionTimeOutMs, zkConnectionTimeoutMs,
      zkMaxInFlightRequests, time, "kafka.security", "AzPubSubSimpleAclAuthorizer")
    zkClient.createAclPaths()

    startZkChangeListeners()
    loadCache()
  }

  /**
    * authorizing each request.
    * if the principal type is SAML token, we need to ensure the token is not expired, despite of the resource type being accessed.
    * if the request is accessing topic resource, we will do topic authorization; for other type of source,like CLUSTER,
    * the request should be coming from cluster internal, this kinds of requests should be always allowed.
    * If the request is coming from channels like PLAINTEXT or SSL, the principal created by Kafka is "User:ANONYMOUS",
    * we need to make sure in AzPubSubRegistrar (Topics-Prod.ini) the ANONYMOUS user is granted with appropriate permission.
    *
    * @param session the current connection context, authorizationId is saved in the session
    * @param operation Operation type, options are: Read, Write, Delete, Describe, All
    * @param resource Resource being access, in format of ResourceType:ResourceName, e.g., Topic:kattesttopic
    * @return
    */
  override def authorize(session: Session, operation: Operation, resource: Resource): Boolean = {

    LOGGER.info(s"principal: ${Try(session.principal.getName).getOrElse("Empty principal name")}, Operation: ${operation.name}")

    newGauge(
      AzPubSubAclAuthorizer.AzPubSubAclAuthorizingRequest,
      new Gauge[Int] {
        def value = 1
      })

    resource.resourceType match {

      case Topic => {

        val acls = getAcls(resource) ++ getAcls(new Resource(resource.resourceType, Resource.WildCardResource))

        LOGGER.debug(s"Acls read from Zookeeper, length: ${acls.size}")

        session.principal.getPrincipalType match {

          /**
            * If principal is regular User, including anonymous use, directly match the acl configured in Topic-Prod.ini.
            * As mentioned above, for regular PLAINTEXT ans SSL channel, the principal is: User:ANONYMOUS
            *
            */
          case KafkaPrincipal.USER_TYPE => aclMatch(operation, resource, session.principal, session.clientAddress.getHostAddress, Allow, acls)

          /**
            * If the connection session is using SAML2 token, check if any claim of the token has permission to the topic, which is configured in Topic-Prod.ini
            */
          case KafkaPrincipal.TOKEN_TYPE => {

            /**
              * Check if the current session is using SAML token as authorization id.
              * If it is, retrieve the token and deserialize the JSON string into object of Token class
              */

            val token   = Json.parseFull(session.principal.getName).get.asJsonObject

            /**
              *  If there's a token, then validate if the token is still valid - token not expired.
              */
            val formatter = new SimpleDateFormat(AzPubSubAclAuthorizer.Saml2TokenTimeFormatter, Locale.ENGLISH)
            formatter.setTimeZone(TimeZone.getTimeZone("UTC"))
            val validFrom = formatter.parse(token("ValidFrom").to[String])
            val validTo = formatter.parse(token("ValidTo").to[String])
            val utcNowString = formatter.format(new Date)
            val currentMoment = formatter.parse(utcNowString)

            if(!cacheTokenLastValidatedTime.contains(token("UniqueId").toString)) {
              cacheTokenLastValidatedTime += (token("UniqueId").toString -> new Date(0L))
            }

            if(cacheTokenLastValidatedTime(token("UniqueId").toString).toInstant.plus(60, ChronoUnit.MINUTES).isBefore(currentMoment.toInstant)) {

              if(false == tokenAuthenticator.validate(token("Base64Token").to[String])){
                return false
              }

              cacheTokenLastValidatedTime(token("UniqueId").toString) = currentMoment
            }

            if( currentMoment.before(validFrom)){

              LOGGER.warn(s"The ValidFrom date time of the token is in the future, this is invalid. ValidFrom: ${token("ValidFrom")}, now: ${ currentMoment}")

              newTimer(AzPubSubAclAuthorizer.TokenInvalidFromDatetimeRateMs, TimeUnit.MILLISECONDS, TimeUnit.SECONDS)

              return false
            }

            if( currentMoment.after(validTo)) {

              LOGGER.warn(s"The token has already expired. ValidTo: ${token("ValidTo")}, now: ${currentMoment}")

              newTimer(AzPubSubAclAuthorizer.TokenExpiredRateMs, TimeUnit.MILLISECONDS, TimeUnit.SECONDS)

              return false
            }

            LOGGER.info(s"Token is valid. ValidFrom: ${token("ValidFrom")}, ValidTo: ${token("ValidTo")}")

            token("Roles").asJsonArray.iterator.map(_.to[String]).foreach(r => {
              LOGGER.debug(s"Claim from json token: ${r}")
              val prin = new KafkaPrincipal(KafkaPrincipal.ROLE_TYPE, r)

              if(aclMatch(operation, resource, prin, session.clientAddress.getHostAddress, Allow, acls)){

                LOGGER.info(s"Authorization for ${prin} operation ${operation} on resource ${resource} succeeded.")

                newTimer(AzPubSubAclAuthorizer.TopicAuthorizationUsingTokenSuccessfulRateMs, TimeUnit.MILLISECONDS, TimeUnit.SECONDS)

                return true
              }
            })

            LOGGER.warn(s"The token doesn't have any role permitted to access the particular topic ${resource.name}.")

            newTimer(AzPubSubAclAuthorizer.TokenNotAuthorizedForTopicRateMs, TimeUnit.MILLISECONDS, TimeUnit.SECONDS)

            return false
          }
          case _ => {
            LOGGER.warn(s"unknown principal rejected: ${session.principal}, accessing resource: ${resource}, operation: ${operation}")

            return false
          }
        }
      }
      case _ => {

        /**
          * If the client is trying to access other resources like "Cluster/Group/DelegationToken/TxnId",
          * This kind of requests should be always coming from brokers of the current cluster; otherwise, the request should be rejected.
          */

        LOGGER.debug(s"session client address: ${session.clientAddress.getHostAddress}")

        if(!brokerHosts.contains(session.clientAddress.getHostAddress)) {

          val allBrokers = zkClient.getAllBrokersInCluster

          allBrokers.foreach(b => b.endPoints.foreach(e => {

            brokerHosts += InetAddress.getByName(e.host).getHostAddress

            LOGGER.debug(s"Kafka broker host : ${e.host}")
          }))
        }

        if(!brokerHosts.contains (session.clientAddress.getHostAddress) ){

          LOGGER.warn(s"Client is not broker and accessing ${resource.resourceType} rejected: ${session.clientAddress.getHostAddress}")

          return false
        }

        LOGGER.debug(s"Client is broker and accessing ${resource.resourceType} allowed: ${session.clientAddress.getHostAddress}")

        return true
      }
    }
  }

  protected def aclMatch(operations: Operation, resource: Resource, principal: KafkaPrincipal, host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {

    acls.find { acl =>

      acl.permissionType == permissionType &&
        (acl.principal == principal
          || (principal.getPrincipalType == KafkaPrincipal.USER_TYPE && acl.principal == KafkaPrincipal.WildCardUserTypePrincipal)
          || (principal.getPrincipalType == KafkaPrincipal.ROLE_TYPE && acl.principal == KafkaPrincipal.WildCardRoleTypePrincipal ) ) &&
        (operations == acl.operation || acl.operation == All) &&
        (acl.host == host || acl.host == Acl.WildCardHost)
    }.exists {

      acl =>
        LOGGER.debug(s"operation = $operations on resource = $resource from host = $host is $permissionType based on acl = $acl")

        true
    }
  }

  object AclChangedNotificationHandler extends NotificationHandler {
    override def processNotification(notificationMessage: Array[Byte]) {
      val resource: Resource = Resource.fromString(new String(notificationMessage, StandardCharsets.UTF_8))
      inWriteLock(lock) {
        val versionedAcls = getAclsFromZk(resource)
        updateCache(resource, versionedAcls)
      }
    }
  }

  override def addAcls(acls: Set[Acl], resource: Resource) {
    if (acls != null && acls.nonEmpty) {
      inWriteLock(lock) {
        updateResourceAcls(resource) { currentAcls =>
          currentAcls ++ acls
        }
      }
    }
  }

  override def removeAcls(aclsTobeRemoved: Set[Acl], resource: Resource): Boolean = {
    inWriteLock(lock) {
      updateResourceAcls(resource) { currentAcls =>
        currentAcls -- aclsTobeRemoved
      }
    }
  }

  override def removeAcls(resource: Resource): Boolean = {
    inWriteLock(lock) {
      val result = zkClient.deleteResource(resource)
      updateCache(resource, VersionedAcls(Set(), 0))
      updateAclChangedFlag(resource)
      result
    }
  }

  override def getAcls(resource: Resource): Set[Acl] = {
    inReadLock(lock) {
      aclCache.get(resource).map(_.acls).getOrElse(Set.empty[Acl])
    }
  }

  override def getAcls(principal: KafkaPrincipal): Map[Resource, Set[Acl]] = {
    inReadLock(lock) {
      aclCache.mapValues { versionedAcls =>
        versionedAcls.acls.filter(_.principal == principal)
      }.filter { case (_, acls) =>
        acls.nonEmpty
      }.toMap
    }
  }

  override def getAcls(): Map[Resource, Set[Acl]] = {
    inReadLock(lock) {
      aclCache.mapValues(_.acls).toMap
    }
  }

  def close() {
    if (aclChangeListener != null) aclChangeListener.close()
    if (zkClient != null) zkClient.close()
  }


  private[auth] def startZkChangeListeners(): Unit = {
    aclChangeListener = new ZkNodeChangeNotificationListener(zkClient, AclChangeNotificationZNode.path, AclChangeNotificationSequenceZNode.SequenceNumberPrefix, AclChangedNotificationHandler)
    aclChangeListener.init()
  }

  private def updateCache(resource: Resource, versionedAcls: VersionedAcls) {
    if (versionedAcls.acls.nonEmpty) {
      aclCache.put(resource, versionedAcls)
    } else {
      aclCache.remove(resource)
    }
  }

  private def getAclsFromZk(resource: Resource): VersionedAcls = {
    zkClient.getVersionedAclsForResource(resource)
  }

  private def loadCache()  {
    inWriteLock(lock) {
      val resourceTypes = zkClient.getResourceTypes()
      for (rType <- resourceTypes) {
        val resourceType = ResourceType.fromString(rType)
        val resourceNames = zkClient.getResourceNames(resourceType.name)
        for (resourceName <- resourceNames) {
          val versionedAcls = getAclsFromZk(Resource(resourceType, resourceName))
          updateCache(new Resource(resourceType, resourceName), versionedAcls)
        }
      }
    }
  }

  private def updateAclChangedFlag(resource: Resource) {
    zkClient.createAclChangeNotification(resource.toString)
  }

  /**
    * Safely updates the resources ACLs by ensuring reads and writes respect the expected zookeeper version.
    * Continues to retry until it successfully updates zookeeper.
    *
    * Returns a boolean indicating if the content of the ACLs was actually changed.
    *
    * @param resource the resource to change ACLs for
    * @param getNewAcls function to transform existing acls to new ACLs
    * @return boolean indicating if a change was made
    */
  private def updateResourceAcls(resource: Resource)(getNewAcls: Set[Acl] => Set[Acl]): Boolean = {
    var currentVersionedAcls =
      if (aclCache.contains(resource))
        getAclsFromCache(resource)
      else
        getAclsFromZk(resource)
    var newVersionedAcls: VersionedAcls = null
    var writeComplete = false
    var retries = 0
    while (!writeComplete && retries <= maxUpdateRetries) {
      val newAcls = getNewAcls(currentVersionedAcls.acls)
      val (updateSucceeded, updateVersion) =
        if (newAcls.nonEmpty) {
          zkClient.conditionalSetOrCreateAclsForResource(resource, newAcls, currentVersionedAcls.zkVersion)
        } else {
          trace(s"Deleting path for $resource because it had no ACLs remaining")
          (zkClient.conditionalDelete(resource, currentVersionedAcls.zkVersion), 0)
        }

      if (!updateSucceeded) {
        trace(s"Failed to update ACLs for $resource. Used version ${currentVersionedAcls.zkVersion}. Reading data and retrying update.")
        Thread.sleep(backoffTime)
        currentVersionedAcls = getAclsFromZk(resource)
        retries += 1
      } else {
        newVersionedAcls = VersionedAcls(newAcls, updateVersion)
        writeComplete = updateSucceeded
      }
    }

    if(!writeComplete)
      throw new IllegalStateException(s"Failed to update ACLs for $resource after trying a maximum of $maxUpdateRetries times")

    if (newVersionedAcls.acls != currentVersionedAcls.acls) {
      debug(s"Updated ACLs for $resource to ${newVersionedAcls.acls} with version ${newVersionedAcls.zkVersion}")
      updateCache(resource, newVersionedAcls)
      updateAclChangedFlag(resource)
      true
    } else {
      debug(s"Updated ACLs for $resource, no change was made")
      updateCache(resource, newVersionedAcls)
      false
    }
  }

  private def backoffTime = {
    retryBackoffMs + Random.nextInt(retryBackoffJitterMs)
  }

  private def getAclsFromCache(resource: Resource): VersionedAcls = {
    aclCache.getOrElse(resource, throw new IllegalArgumentException(s"ACLs do not exist in the cache for resource $resource"))
  }
}
