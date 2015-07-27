package org.novetta.zoo.actors

/**
 * This actor will register itself to deliver messages to the RabbitMQ server.
 */

import akka.actor.{Props, Actor, ActorLogging}
import com.rabbitmq.client.{Channel, Connection, _}
import org.json4s.jackson.Serialization
import org.novetta.zoo.types._
import scala.concurrent.duration.{FiniteDuration, _}
import org.json4s._
import org.json4s.JsonDSL._
import org.json4s.jackson.JsonMethods._
import org.json4s.jackson.Serialization

/**
 * @constructor This is the companion object to the class. Simplifies Props() nonsense.
 */
object RabbitProducerActor {
  def props(host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, requeueKey: String, misbehaveKey: String): Props = {
    Props(new RabbitProducerActor(host, exchange, queue, requeueKey, misbehaveKey) )
  }
}


/**
 * This actor will register itself to deliver messages to the RabbitMQ server. This gets a dedicated thread, and a
 * new producer should be created for each exchange that we need to deliver to. This is a cleaner design overall. Should
 * multiple exchanges be needed, their dispatcher will get a dedicated thread, and the actors themselves, as they are lightweight
 * processes, will share it.
 *
 * Something like:
 * {{{
 * val myGetter: ActorRef = system.actorOf(RabbitProducerActor.props(hostConfig, exchangeConfig), "producer")
 * }}}
 * is the preferred way to create this actor.
 *
 * The following is a listing of the message types that this Actor explicitly handles, and a brief discussion of their purpose.
 * {{{
 *  case r: Result =>
 *    When a new RMQ message is returned from the callback, take it, attempt to parse the ZooWork JSON out of it, and pass to the
 *    WorkGroup actor for handling. Decrement totalDemand, so that we do not attempt to consume the world.
 *  }
 *
 *  case ResultPackage(filename: String, results: Iterable[WorkResult], md5: String, sha1: String, sha256: String) =>
 *    After processing work, WorkPackages are submitted containing all component elements, be they failures or successes
 *  }
 *
 *  case ZooWork(primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], attempts: Int) =>
 *
 *  }
 * }}}
 *
 * @constructor Create a new RabbitProducerActor, which consumes Scala formatted objects for serialization and delivery
 *             to RMQ. An example of such a message is a ZooWork, which is serialized to a JSON string, and sent to RMQ
 *             for reanalysis.
 * @param host: a HostSettings object, responsible for holding the server configuration to use.
 * @param exchange: an ExchangeSettings object, holds the exchange configuration.
 * @param queue: a QueueSettings object, holds the queue configuration.
 * @param requeueKey: the requeueKey from the configuration file, used as the queue that Jobs will be requeued into.
 * @param misbehaveKey: the key used to tag messages that have exhibited continual problems when being processed.
 */

class RabbitProducerActor(host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, requeueKey: String, misbehaveKey: String) extends Actor with ActorLogging {
  var channel: Channel =_
  var connection: Connection =_
  var totalDemand = 0

  implicit val formats = org.json4s.DefaultFormats
  override def preStart() = {
    val reconnectionDelay: FiniteDuration = 10.seconds
    val factory: ConnectionFactory = new ConnectionFactory()
    factory.setHost(host.host)
    factory.setPort(host.port)
    factory.setUsername(host.user)
    factory.setPassword(host.password)
    factory.setVirtualHost(host.vhost)

    this.connection = factory.newConnection()
    this.channel = connection.createChannel()

    this.channel.exchangeDeclare(exchange.exchangeName, exchange.exchangeType, exchange.durable)
    this.channel.queueDeclare(queue.queueName, queue.durable, queue.exclusive, queue.autodelete, null)
    this.channel.queueBind(queue.queueName, exchange.exchangeName, queue.routingKey)
    log.info("Exchange {} should be made", exchange.exchangeName)

  }
  /**
   * Helper function to prepare a message for RMQ.
   *
   * @return A Duration object representing the delta between origin and current.
   * @param message: An RMQSendMessage object, which is then directly published.
   */
  def sendMessage(message: RMQSendMessage) = {
    this.channel.basicPublish(exchange.exchangeName, message.routingKey, null, message.body)
  }

  def receive = {
    case Send(message: RMQSendMessage) =>
      sendMessage(message)
      log.info("Sent to RMQ: {}", new String(message.body))

    case r: Result =>
      val json = (
        ("filename" -> r.filename) ~
          ("data" -> r.result.data)
        )
      val j = compact(render(json))
      sendMessage(RMQSendMessage(j.getBytes, r.result.routingKey))

    case ResultPackage(filename: String, results: Iterable[WorkResult], md5: String, sha1: String, sha256: String) => //work can get lost here. Need to make sure that doesnt happen.
      results.foreach({ result =>

        val json = (
          ("filename" -> filename) ~
            ("data" -> result.data) ~
            ("md5" -> md5) ~
            ("sha1" -> sha1) ~
            ("sha256" -> sha256)
          )
        val j = compact(render(json))
        sendMessage(RMQSendMessage(j.getBytes, result.routingKey))
      })
      sender ! ResultResolution(true)
      log.info("emitting result {} to RMQ", sender().path)

    case ZooWork(primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], attempts: Int) =>
      val incremented_attempts = attempts + 1
      val json = (
        ("primaryURI" -> primaryURI) ~
          ("secondaryURI" -> secondaryURI) ~
          ("filename" -> filename) ~
          ("tasks" -> Serialization.write(tasks)) ~
          ("attempts" -> incremented_attempts)
        )
      val j = compact(render(json))
      if(incremented_attempts <= 3) {
        sendMessage(RMQSendMessage(j.getBytes, requeueKey))
        log.info("emitting a ZooWork {} to RMQ", j)
      } else {
        sendMessage(RMQSendMessage(j.getBytes, misbehaveKey))
        log.info("emitting misbehaving ZooWork {} to RMQ", j)
      }
      sender ! RemainderResolution(true)
      log.info("emitting gunslinger from {}", sender().path)

    case msg =>
      log.error("RabbitProducerActor has received a message it cannot match against: {}", msg)
  }
}