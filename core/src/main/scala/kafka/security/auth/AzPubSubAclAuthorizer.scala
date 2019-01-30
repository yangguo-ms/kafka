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

import com.google.gson.Gson
import com.typesafe.scalalogging.Logger
import kafka.network.RequestChannel.Session
import kafka.utils._
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.common.security.saml.Token

import scala.util.Try
import org.apache.kafka.common.utils.{SecurityUtils, Time}


class AzPubSubAclAuthorizer extends SimpleAclAuthorizer with Logging {
  private val authorizerLogger = Logger("kafka.authorizer.logger")

  //
  // authorizing each request.
  // if the principal type is SAML token, we need to ensure the token is not expired, despite of the resource type being accessed.
  // if the request is accessing topic resource, we will do topic authorization; for other type of source,like CLUSTER,
  // the request should be coming from cluster internal, this kinds of requests should be always allowed.
  // If the request is coming from channels like PLAINTEXT or SSL, the principal created by Kafka is "User:ANONYMOUS",
  // we need to make sure in AzPubSubRegistrar (Topics-Prod.ini) the ANONYMOUS user is granted with appropriate permission.
  //
  override def authorize(session: Session, operation: Operation, resource: Resource): Boolean = {
    authorizerLogger.info("principal: {}, Operation: {}", Try(session.principal.getName).getOrElse("Empty principal name"), operation.name)

    var token:Token = null
    if(Try(session.principal.getPrincipalType).getOrElse("") == KafkaPrincipal.Token_Type){
      val gson = new Gson()
      token = gson.fromJson(session.principal.getName, classOf[Token])
      if(null == token){
        authorizerLogger.warn("failed to deserialize JSON token, token json string: {}", session.principal.getName)
        return false
      }

      if(system.DateTime.Compare(token.ValidFrom, system.DateTime.getUtcNow) > 0){
        authorizerLogger.warn("The ValidFrom date time of the token is in the future, this is invalid. ValidFrom: {}, now: {}", token.ValidFrom, system.DateTime.getUtcNow);
        return false
      }
      if(system.DateTime.Compare(system.DateTime.getUtcNow, token.ValidTo) > 0){
        authorizerLogger.warn("The token has already expired. ValidTo: {}, now: {}", token.ValidTo, system.DateTime.getUtcNow);
        return false
      }
      authorizerLogger.info("Token is valid. ValidFrom: {}, ValidTo:", token.ValidFrom, token.ValidTo);
    }

    resource.resourceType match {

      case Topic => {

        val acls = getAcls(resource) ++ getAcls(new Resource(resource.resourceType, Resource.WildCardResource))

        authorizerLogger.debug("Acls read from Zookeeper, length: {}", acls.size)

        session.principal.getPrincipalType match {

          case KafkaPrincipal.USER_TYPE => aclMatch(operation, resource, session.principal, session.clientAddress.getHostAddress, Allow, acls)

          case KafkaPrincipal.Token_Type=> {
            token.Claims.foreach(c => {

              authorizerLogger.debug("Claim from json token: {}", c.getValue)

              val prin = new KafkaPrincipal(KafkaPrincipal.Role_Type, c.getValue)

              if(aclMatch(operation, resource, prin, session.clientAddress.getHostAddress, Allow, acls)){

                authorizerLogger.info("Authorization for {} operation {} on resource {} succeeded.", prin, operation, resource)

                return true
              }
            })

            authorizerLogger.warn("Token is not authorized...")

            return false
          }
          case _ => {

            authorizerLogger.warn("unknown principal rejected: {}, accessing resource: {}, operation: {}", session.principal, resource, operation);

            return false
          }
        }
      }
      case _ => return true
    }
  }

  protected override def aclMatch(operations: Operation, resource: Resource, principal: KafkaPrincipal, host: String, permissionType: PermissionType, acls: Set[Acl]): Boolean = {
    acls.find { acl =>
      acl.permissionType == permissionType &&
        (acl.principal == principal
          || (principal.getPrincipalType == KafkaPrincipal.USER_TYPE && acl.principal == Acl.wildCardUserTypePrincipal)
          || (principal.getPrincipalType == KafkaPrincipal.Role_Type && acl.principal == Acl.wildCardRoleTypePrincipal ) ) &&
        (operations == acl.operation || acl.operation == All) &&
        (acl.host == host || acl.host == Acl.WildCardHost)
    }.exists { acl =>
      authorizerLogger.debug(s"operation = $operations on resource = $resource from host = $host is $permissionType based on acl = $acl")
      true
    }
  }
}
