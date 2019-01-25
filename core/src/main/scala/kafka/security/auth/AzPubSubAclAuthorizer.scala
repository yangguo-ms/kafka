/**
  * Licensed to the Apache Software Foundation (ASF) under one or more
  * contributor license agreements.  See the NOTICE file distributed with
  * this work for additional information regarding copyright ownership.
  * The ASF licenses this file to You under the Apache License, Version 2.0
  * (the "License"); you may not use this file except in compliance with
  * the License.  You may obtain a copy of the License at
  *
  * http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
package kafka.security.auth

import java.nio.charset.StandardCharsets
import java.util
import java.util.concurrent.locks.ReentrantReadWriteLock

import com.google.gson.Gson
import com.typesafe.scalalogging.Logger
import kafka.common.{NotificationHandler, ZkNodeChangeNotificationListener}
import kafka.network.RequestChannel.Session
import kafka.security.auth.SimpleAclAuthorizer.VersionedAcls
import kafka.server.KafkaConfig
import kafka.utils.CoreUtils.{inReadLock, inWriteLock}
import kafka.utils._
import kafka.zk.{AclChangeNotificationSequenceZNode, AclChangeNotificationZNode, KafkaZkClient}
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.common.utils.{SecurityUtils, Time}

import scala.collection.JavaConverters._
import scala.util.{Random, Try}
import org.apache.kafka.common.security.plain.Token
/*
object AzPubSubAclAuthorizer {
  //optional override zookeeper cluster configuration where acls will be stored, if not specified acls will be stored in
  //same zookeeper where all other kafka broker info is stored.
  val ZkUrlProp = "authorizer.zookeeper.url"
  val ZkConnectionTimeOutProp = "authorizer.zookeeper.connection.timeout.ms"
  val ZkSessionTimeOutProp = "authorizer.zookeeper.session.timeout.ms"
  val ZkMaxInFlightRequests = "authorizer.zookeeper.max.in.flight.requests"

  //List of users that will be treated as super users and will have access to all the resources for all actions from all hosts, defaults to no super users.
  val SuperUsersProp = "super.users"
  //If set to true when no acls are found for a resource , authorizer allows access to everyone. Defaults to false.
  val AllowEveryoneIfNoAclIsFoundProp = "allow.everyone.if.no.acl.found"

//  case class VersionedAcls(acls: Set[Acl], zkVersion: Int)
}
*/
class AzPubSubAclAuthorizer extends SimpleAclAuthorizer with Logging {
  private val authorizerLogger = Logger("kafka.authorizer.logger")
  private var superUsers = Set.empty[KafkaPrincipal]
  private var shouldAllowEveryoneIfNoAclIsFound = false
  private var zkClient: KafkaZkClient = null
  private var aclChangeListener: ZkNodeChangeNotificationListener = null
  private val aclCache = new scala.collection.mutable.HashMap[Resource, VersionedAcls]
  private val lock = new ReentrantReadWriteLock()

  // The maximum number of times we should try to update the resource acls in zookeeper before failing;
  // This should never occur, but is a safeguard just in case.
  //protected[auth] var maxUpdateRetries = 10

  private val retryBackoffMs = 100
  private val retryBackoffJitterMs = 50

  //
  // authorizing each request.
  // if the principal type is SAML token, we need to ensure the token is not expired, despite of the resource type being accessed.
  // if the request is accessing topic resource, we will do topic authorization; for other type of source,like CLUSTER,
  // the request should be coming from cluster internal, this kinds of requests should be allowed.
  //
  override def authorize(session: Session, operation: Operation, resource: Resource): Boolean = {
    authorizerLogger.info("principal: {}, Operation: {}", Try(session.principal.getName).getOrElse("Empty principal name"), operation.name)

    var token:Token = null
    if(Try(session.principal.getPrincipalType).getOrElse("") == KafkaPrincipal.Token_Type){
      val gson = new Gson()
      token = gson.fromJson(session.principal.getName, classOf[Token])
      if(null == token){
        authorizerLogger.warn("failed to deserialize JSON token")
        return false
      }

      if(system.DateTime.Compare(system.DateTime.getUtcNow, token.ValidFrom) > 0 || system.DateTime.Compare(system.DateTime.getUtcNow, token.ValidTo) > 0){
        authorizerLogger.warn("Token is already expired. authorization is failed.")
        return false
      }
    }

    resource.resourceType match {
      case Topic => {
        val acls = getAcls(resource) ++ getAcls(new Resource(resource.resourceType, Resource.WildCardResource))
        session.principal.getPrincipalType match {
          case KafkaPrincipal.USER_TYPE => aclMatch(operation, resource, session.principal, session.clientAddress.getHostAddress, Allow, acls)
          case KafkaPrincipal.Token_Type=> {
            token.Claims.foreach(c => {
              authorizerLogger.info("Claim from json token: {}", c.getValue)
              val prin = new KafkaPrincipal(KafkaPrincipal.Role_Type, c.getValue)
              if(aclMatch(operation, resource, prin, session.clientAddress.getHostAddress, Allow, acls)){
                authorizerLogger.info("Authorization for {} operation {} on resource {} succeeded.", prin, operation, resource)
                true
              }
            })
            return false
          }
          case _ => {
            authorizerLogger.warn("unknown principal: {}, accessing resource: {}, operation: {}", session.principal, resource, operation);
            return false
          }
        }
      }
      case _ => return true
    }
  }
}
