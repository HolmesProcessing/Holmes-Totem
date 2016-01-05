package org.novetta.zoo.driver

import java.util.concurrent.{Executors, ExecutorService}

import akka.actor.{ActorRef, ActorSystem, Props}
import org.novetta.zoo.actors._
import org.novetta.zoo.services.peinfo.{PEInfoSuccess, PEInfoWork}
import org.novetta.zoo.services.virustotal.{VirustotalSuccess, VirustotalWork}
import org.novetta.zoo.services.yara.{YaraSuccess, YaraWork}
import org.novetta.zoo.services.{MetadataSuccess, MetadataWork}
import org.novetta.zoo.types._

import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.jackson.JsonMethods._
import akka.routing.RoundRobinPool
import org.novetta.zoo.util.Instrumented

import java.io.File

import com.typesafe.config.{Config, ConfigFactory}

import scala.util.Random

object driver extends App with Instrumented {
  lazy val execServ: ExecutorService = Executors.newFixedThreadPool(4000)
  val conf: Config = if (args.length > 0) {
    println("we have args > 0, using args")
    ConfigFactory.parseFile(new File(args(0)))

  } else {
    ConfigFactory.parseFile(new File("/Users/totem/novetta/totem/config/totem.conf"))
  }
  val system = ActorSystem("totem")

  val hostConfig = HostSettings(
    conf.getString("totem.rabbit_settings.host.server"),
    conf.getInt("totem.rabbit_settings.host.port"),
    conf.getString("totem.rabbit_settings.host.username"),
    conf.getString("totem.rabbit_settings.host.password"),
    conf.getString("totem.rabbit_settings.host.vhost")
  )

  val exchangeConfig = ExchangeSettings(
    conf.getString("totem.rabbit_settings.exchange.name"),
    conf.getString("totem.rabbit_settings.exchange.type"),
    conf.getBoolean("totem.rabbit_settings.exchange.durable")
  )
  val workqueueConfig = QueueSettings(
    conf.getString("totem.rabbit_settings.workqueue.name"),
    conf.getString("totem.rabbit_settings.workqueue.routing_key"),
    conf.getBoolean("totem.rabbit_settings.workqueue.durable"),
    conf.getBoolean("totem.rabbit_settings.workqueue.exclusive"),
    conf.getBoolean("totem.rabbit_settings.workqueue.autodelete")
  )
  val resultQueueConfig = QueueSettings(
    conf.getString("totem.rabbit_settings.resultsqueue.name"),
    conf.getString("totem.rabbit_settings.resultsqueue.routing_key"),
    conf.getBoolean("totem.rabbit_settings.resultsqueue.durable"),
    conf.getBoolean("totem.rabbit_settings.resultsqueue.exclusive"),
    conf.getBoolean("totem.rabbit_settings.resultsqueue.autodelete")
  )

  class TotemicEncoding(conf: Config) extends ConfigTotemEncoding(conf) {
    def GeneratePartial(work: String): String = {
      work match {
        case "FILE_METADATA" => Random.shuffle(services.getOrElse("metadata", List())).head
        case "HASHES" => Random.shuffle(services.getOrElse("hashes", List())).head
        case "PE_INFO" => Random.shuffle(services.getOrElse("peinfo", List())).head
        case "VIRUSTOTAL" => Random.shuffle(services.getOrElse("virustotal", List())).head
        case "YARA" => Random.shuffle(services.getOrElse("yara", List())).head
      }
    }

    def enumerateWork(key: Long, filename: String, workToDo: Map[String, List[String]]): List[TaskedWork] = {
      val w = workToDo.map({
        case ("FILE_METADATA", li: List[String]) =>
          MetadataWork(key, filename, 60, "FILE_METADATA", GeneratePartial("FILE_METADATA"), li)

        case ("PE_INFO", li: List[String]) =>
          PEInfoWork(key, filename, 60, "PE_INFO", GeneratePartial("PE_INFO"), li)

        case ("VIRUSTOTAL", li: List[String]) =>
          VirustotalWork(key, filename, 60, "VIRUSTOTAL", GeneratePartial("VIRUSTOTAL"), li)

        case ("YARA", li: List[String]) =>
          YaraWork(key, filename, 60, "YARA", GeneratePartial("YARA"), li)

        case (s: String, li: List[String]) =>
          UnsupportedWork(key, filename, 1, s, GeneratePartial(s), li)

        case _ => Unit
      }).collect({
        case x: TaskedWork => x
      })
      w.toList
    }

    def workRoutingKey(work: WorkResult): String = {
      work match {
        case x: PEInfoSuccess => conf.getString("totem.enrichers.peinfo.resultRoutingKey")
        case x: MetadataSuccess => conf.getString("totem.enrichers.metadata.resultRoutingKey")
        case x: VirustotalSuccess => conf.getString("totem.enrichers.virustotal.resultRoutingKey")
        case x: YaraSuccess => conf.getString("totem.enrichers.yara.resultRoutingKey")
      }
    }
  }

  val encoding = new TotemicEncoding(conf)

  val myGetter: ActorRef = system.actorOf(RabbitConsumerActor.props[ZooWork](hostConfig, exchangeConfig, workqueueConfig, encoding, Parsers.parseJ).withDispatcher("akka.actor.my-pinned-dispatcher"), "consumer")
  val mySender: ActorRef = system.actorOf(Props(classOf[RabbitProducerActor], hostConfig, exchangeConfig, resultQueueConfig, conf.getString("totem.requeueKey"), conf.getString("totem.misbehaveKey")), "producer")


  // Demo & Debug Zone
  val zoowork = ZooWork("http://localhost/rar.exe", "http://localhost/rar.exe", "winrar.exe", Map[String, List[String]]("YARA" -> List[String]()), 0)

  val json = (
    ("primaryURI" -> zoowork.primaryURI) ~
      ("secondaryURI" -> zoowork.secondaryURI) ~
      ("filename" -> zoowork.filename) ~
      ("tasks" -> zoowork.tasks) ~
      ("attempts" -> zoowork.attempts)
    )

  private[this] val loading = metrics.timer("loading")

  val j = loading.time({
    compact(render(json))
  })

  mySender ! Send(RMQSendMessage(j.getBytes, workqueueConfig.routingKey))

  println("Totem is Running! \nVersion: " + conf.getString("zoo.version"))
}
