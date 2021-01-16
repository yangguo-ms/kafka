package com.microsoft.azpubsub.kafka.admin
import kafka.admin.AclCommand
import kafka.admin.AclCommand.{AclCommandOptions, AdminClientService}
import kafka.utils.{CommandLineUtils, Exit, Json, Logging}
import org.apache.kafka.common.acl.{AccessControlEntry, AclOperation, AclPermissionType}
import org.apache.kafka.common.resource.{ResourcePattern, ResourcePatternFilter, ResourceType}
import org.apache.kafka.common.security.auth.KafkaPrincipal
import org.apache.kafka.common.utils.Utils

import scala.jdk.CollectionConverters._
import scala.collection.mutable

object AzPubSubAclCommand extends Logging {

  def main(args: Array[String]): Unit = {

    val opts = new AzPubSubAclCommandOptions(args)

    CommandLineUtils.printHelpAndExitIfNeeded(opts, "This tool helps to manage acls on kafka.")

    opts.checkArgs()

    val aclCommandService = new AzPubSubAdminClientService(opts)

    var exitCode = 0

    try {
      if (opts.options.has(opts.addOpt))
        aclCommandService.addAcls()
      else if (opts.options.has(opts.removeOpt))
        aclCommandService.removeAcls()
      else if (opts.options.has(opts.listOpt))
        aclCommandService.listAcls()
    } catch {
      case e: Throwable =>
        println(s"Error while executing ACL command: ${e.getMessage}")
        println(Utils.stackTrace(e))
        exitCode = 1
    } finally {
      Exit.exit(exitCode)
    }
  }
}

class AzPubSubAdminClientService(opts: AzPubSubAclCommandOptions) extends AdminClientService(opts) {

  override def printAcls(filters: Set[ResourcePatternFilter], listPrincipals: Set[KafkaPrincipal], resourceToAcls: Map[ResourcePattern, Set[AccessControlEntry]]): Unit = {
    if (!opts.options.has(opts.outputAsProducerConsumerOpt)) {
      super.printAcls(filters, listPrincipals, resourceToAcls)
      return
    }
    if (listPrincipals.isEmpty) {
      val producerConsumerAclMap = aclToProducerConsumerMapping(resourceToAcls);
      outputAsJson(producerConsumerAclMap)
    }
    else {
      val allPrincipalsFilteredResourceToAcls = resourceToAcls.view.mapValues(acls =>
        acls.filterNot(acl => listPrincipals.forall(
          principal => !principal.toString.equals(acl.principal)))).filter(entry => entry._2.nonEmpty).toMap
      val producerConsumerAclMap = aclToProducerConsumerMapping(allPrincipalsFilteredResourceToAcls)
      outputAsJson(producerConsumerAclMap)
    }
  }

  def outputAsJson(filteredResourceToAcls: mutable.Map[ResourcePattern, mutable.Set[AzPubSubAccessControlEntry]]): Unit = {
    val resourceList = mutable.Set[Any]()
    for ((resource, acls) <- filteredResourceToAcls) {
      resourceList.add(mutable.Map("acls" -> acls.map(x => mutable.Map("principal" -> x.principal(),
        "host" -> x.host(),
        "operation" -> x.operation().toString,
        "aggregatedOperation" -> x.aggregatedOperation(),
        "permissionType" -> x.permissionType().toString).asJava).asJava,
        "resourceType" -> resource.resourceType().toString,
        "name" -> resource.name(), "patternType" -> resource.patternType().toString
      ).asJava)
    }
    val aclResponse = Json.encodeAsString(Map("resources" -> resourceList.asJava).asJava)
    println("Received Acl information from Kafka")
    println(aclResponse)
  }

  def GetProducerAclOperations(): Set[AclOperation] = {
    val dummyArgs = Array[String]("--bootstrap-server", "localhost:9092", "--add", "--allow-principal", "User:Bob", "--producer", "--topic", "Test-topic")
    val dummyOpt = new AclCommandOptions(dummyArgs)
    val resourceMap = AclCommand.getProducerResourceFilterToAcls(dummyOpt)
    for ((key, value) <- resourceMap) {
      if (key.resourceType() == ResourceType.TOPIC) {
        var aclOperationList = Set[AclOperation]()
        value.foreach(acl => aclOperationList += acl.operation())
        return aclOperationList
      }
    }
    return Set[AclOperation]()
  }

  def GetConsumerAclOperations(): Set[AclOperation] = {
    val dummyArgs = Array[String]("--bootstrap-server", "localhost:9092", "--add", "--allow-principal", "User:Bob", "--consumer", "--topic", "Test-topic", "--group", "Test-group")
    val dummyOpt = new AclCommandOptions(dummyArgs)
    val resourceMap = AclCommand.getConsumerResourceFilterToAcls(dummyOpt)
    for ((key, value) <- resourceMap) {
      if (key.resourceType() == ResourceType.TOPIC) {
        var aclOperationList = Set[AclOperation]()
        value.foreach(acl => aclOperationList += acl.operation())
        return aclOperationList
      }
    }
    return Set[AclOperation]()
  }

  def GetGroupAclOperations(): Set[AclOperation] = {
    val dummyArgs = Array[String]("--bootstrap-server", "localhost:9092", "--add", "--allow-principal", "User:Bob", "--consumer", "--topic", "Test-topic", "--group", "Test-group")
    val dummyOpt = new AclCommandOptions(dummyArgs)
    val resourceMap = AclCommand.getConsumerResourceFilterToAcls(dummyOpt)
    for ((key, value) <- resourceMap) {
      if (key.resourceType() == ResourceType.GROUP) {
        var aclOperationList = Set[AclOperation]()
        value.foreach(acl => aclOperationList += acl.operation())
        return aclOperationList
      }
    }
    return Set[AclOperation]()
  }

  def aclToProducerConsumerMapping(resourceToAcls:Map[ResourcePattern,Set[AccessControlEntry]]):mutable.Map[ResourcePattern,mutable.Set[AzPubSubAccessControlEntry]] = {
    val producerConsumerGroupAclMap = mutable.Map[ResourcePattern, mutable.Set[AzPubSubAccessControlEntry]]()
    val producerAclOperations = GetProducerAclOperations()
    val consumerAclOperations = GetConsumerAclOperations()
    val groupAclOperations = GetGroupAclOperations()

    resourceToAcls.foreach(resource => {
      producerConsumerGroupAclMap += (resource._1 -> mutable.Set[AzPubSubAccessControlEntry]())
      val principalAclMap = mutable.Map[String,mutable.Set[AccessControlEntry]]()
      resource._2.foreach(acl => {
        if (principalAclMap.contains(acl.principal())) {
          principalAclMap(acl.principal()).add(acl)
        }
        else{
          principalAclMap += (acl.principal() -> mutable.Set(acl))
        }
      })
      principalAclMap.foreach { case (principal, acls) => {
        var strayAcls = acls
        val filteredAclOperations = mutable.Set[AclOperation]()
        val filteredAcls = acls.filter(x => (x.host() == "*" && x.permissionType() == AclPermissionType.ALLOW))
        filteredAcls.foreach(x => filteredAclOperations.add(x.operation()))
        if (resource._1.resourceType() == ResourceType.TOPIC) {
          if (producerAclOperations.subsetOf(filteredAclOperations)) {
            strayAcls = strayAcls.filterNot(x => (x.host() == "*" && x.permissionType() == AclPermissionType.ALLOW && producerAclOperations.contains(x.operation())))
            val modifiedAcl = new AzPubSubAccessControlEntry(principal, "*", AclOperation.ANY, AclPermissionType.ALLOW, "PRODUCER")
            producerConsumerGroupAclMap(resource._1).add(modifiedAcl)
          }
          if (consumerAclOperations.subsetOf(filteredAclOperations)) {
            strayAcls = strayAcls.filterNot(x => (x.host() == "*" && x.permissionType() == AclPermissionType.ALLOW && consumerAclOperations.contains(x.operation())))
            val modifiedAcl = new AzPubSubAccessControlEntry(principal, "*", AclOperation.ANY, AclPermissionType.ALLOW, "CONSUMER")
            producerConsumerGroupAclMap(resource._1).add(modifiedAcl)
          }
        }
        else if (resource._1.resourceType() == ResourceType.GROUP) {
          if (groupAclOperations.subsetOf(filteredAclOperations)) {
            strayAcls = strayAcls.filterNot(x => (x.host() == "*" && x.permissionType() == AclPermissionType.ALLOW && groupAclOperations.contains(x.operation())))
            val modifiedAcl = new AzPubSubAccessControlEntry(principal, "*", AclOperation.ANY, AclPermissionType.ALLOW, "GROUP")
            producerConsumerGroupAclMap(resource._1).add(modifiedAcl)
          }
        }
        strayAcls.foreach(acl => {
          val modifiedAcl = new AzPubSubAccessControlEntry(principal, acl.host(), acl.operation(), acl.permissionType(), "NONE")
          producerConsumerGroupAclMap(resource._1).add(modifiedAcl)
        })
      }}
    })
    return producerConsumerGroupAclMap
  }
}

class AzPubSubAclCommandOptions (args: Array[String]) extends AclCommandOptions(args.filterNot(x => (x == "--pc"))){

  val outputAsProducerConsumerOpt = parser.accepts("pc", "output ACL list as producer consumer")
  options = parser.parse(args: _*)
}