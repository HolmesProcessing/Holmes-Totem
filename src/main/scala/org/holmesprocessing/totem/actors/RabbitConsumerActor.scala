package org.holmesprocessing.totem.actors

/**
 * This actor will register itself to consume messages from the RabbitMQ server, transform those messages into native
 * Scala objects, and generate corresponding WorkActors based on those objects.
 *
 */

import java.util.UUID

import akka.actor._
import com.codahale.metrics.Histogram
import com.rabbitmq.client._
import org.json4s._
import org.json4s.jackson.JsonMethods._
import org.holmesprocessing.totem.types._
import org.holmesprocessing.totem.util.MonitoredActor
import scala.concurrent.duration.{FiniteDuration, _}
import org.holmesprocessing.totem.types.WorkEncoding
import org.holmesprocessing.totem.util.DownloadSettings
/**
 * @constructor This is the companion object to the RabbitConsumerActor class.
 */
object RabbitConsumerActor {
  def props[T: Manifest](host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, servicelist: WorkEncoding, decoder: Parsers.Parser[T], downloadconfig: DownloadSettings, taskingconfig: TaskingSettings): Props = {
    Props(new RabbitConsumerActor(host, exchange, queue, servicelist, decoder, downloadconfig, taskingconfig) )
  }
}
/**
 * This actor will register itself to consume messages from the configured RabbitMQ server. This gets a dedicated thread, and a
 * new consumer should be created for each queue that we need to consume from. This is a cleaner design overall. Should
 * multiple queues be needed, their dispatcher will get a dedicated thread. As a result, messages of varying formats should be routed
 * through differing queues, whereas messages of the same format can be routed through the same queue through the use of RMQ topics.
 *
 * This is generally the top of an actor hierarchy, and creates its own WorkGroupActor immediately. The hierarchy resembles
 * Consumer -> WorkGroupActor -*-> WorkActor
 *
 * Something like:
 * {{{
 * val myGetter: ActorRef = system.actorOf(RabbitConsumerActor.props[ZooWork](hostConfig, exchangeConfig, queueConfig, Parsers.parseJ), "consumer")
 * }}}
 * is the preferred way to create this actor.
 *
 * The following is a listing of the message types that this Actor explicitly handles, and a brief discussion of their purpose.
 * {{{
 *   case RabbitMessage(deliveryTag: Long, body: Array[Byte]) => {
 *     When a new RMQ message is returned from the callback, take it, attempt to parse the ZooWork JSON out of it, and pass to the
 *     WorkGroup actor for handling. Decrement totalDemand, so that we do not attempt to consume the world.
 *   }
 *
 *   case Ack(n: Long) => {
 *     After the completion of a provided job, the ConsumerActor must acknowledge that the work has been processed. This is
 *     called regardless of whether or not the Job, or it's component Work elements are successes or failures on the Service
 *     side.
 *   }
 *
 *  case NAck(n: Long) => {
 *    This is provided to NACK a specific job, and allow it to be reprocessed. This is only called if there is a failure within
 *    TOTEM itself, or the binary associated with the Job cannot be successfully downloaded.
 *  }
 * }}}
 *
 * @constructor Create a new RabbitConsumerActor, which consumes JSON formatted RabbitMessages from RMQ, transforms them
 *             into objects of type [T], and emits those objects to the state actor groups.
 * @param host: a HostSettings object, responsible for holding the server configuration to use.
 * @param exchange: an ExchangeSettings object, holds the exchange configuration.
 * @param queue: a QueueSettings object, holds queue configuration.
 * @param servicelist: the WorkEncoding object that is used to parse the component Work elements that comprise a Job
 * @param decoder: a Parsers.Parser[T], which is responsible for transforming the JSON data into a Scala object.
 */

class RabbitConsumerActor[T: Manifest](host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, servicelist: WorkEncoding, decoder: Parsers.Parser[T], downloadconfig: DownloadSettings, taskingconfig: TaskingSettings) extends Actor with ActorLogging with MonitoredActor {
  implicit val formats = DefaultFormats
  var WorkGroupActor: ActorRef =_
  var totalDemand = 0
  var channel: Channel =_

  val resultCounts: Histogram = metricRegistry.histogram(classOf[RabbitConsumerActor[ZooWork]].getName + "ack-map-counts")

  override def preStart() ={
    val reconnectionDelay: FiniteDuration = 10.seconds
    this.WorkGroupActor = context.actorOf(WorkGroup.props())
  }

  val factory: ConnectionFactory = new ConnectionFactory()
  factory.setHost(host.host)
  factory.setPort(host.port)
  factory.setUsername(host.user)
  factory.setPassword(host.password)
  factory.setVirtualHost(host.vhost)

  val connection = factory.newConnection()
  this.channel = connection.createChannel()

  this.channel.exchangeDeclare(exchange.exchangeName, exchange.exchangeType, exchange.durable)
  this.channel.queueDeclare(queue.queueName, queue.durable, queue.exclusive, queue.autodelete, null)
  queue.routingKey.foreach(routingKey => {
    this.channel.queueBind(queue.queueName, exchange.exchangeName, routingKey)
  })

  def consumeOne() = {
    val autoAck: Boolean = false
    val response: GetResponse = channel.basicGet(queue.queueName, autoAck)
    if (response == null) {
      // No message retrieved. Do nothing.
    } else {
      val props: AMQP.BasicProperties = response.getProps
      val body: Array[Byte] = response.getBody
      val deliveryTag: Long = response.getEnvelope.getDeliveryTag
      self ! new RabbitMessage(deliveryTag, body)
    }
  }

  channel.basicQos(taskingconfig.prefetch)

  val consumer = new DefaultConsumer(this.channel) {
    override def handleDelivery(
                                 consumerTag: String,
                                 envelope: Envelope,
                                 properties: AMQP.BasicProperties,
                                 body: Array[Byte]) = {
      log.debug("RabbitConsumer: handle delivery tag - {}, is redeliver - {}, channel - {}", envelope.getDeliveryTag, envelope.isRedeliver, channel.hashCode())

      self ! new RabbitMessage(envelope.getDeliveryTag, body)
    }
  }
  this.channel.basicConsume(queue.queueName, false, consumer)
  def monitoredReceive = {
    case RabbitMessage(deliveryTag: Long, body: Array[Byte]) =>
        try {
          parse(new String(body)).extract[T] match {
            case ZooWork(download: Boolean, primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], tags: List[String], attempts: Int) =>
              log.info("RabbitConsumer: created a ZooWork for {}", filename)
              val uuid_filename: String = UUID.randomUUID().toString
              WorkGroupActor ! Create(
                deliveryTag,
                download,
                primaryURI,
                secondaryURI,
                tags,
                WorkState.create(
                  uuid_filename,
                  filename,
                  servicelist.enumerateWork(
                    deliveryTag,
                    uuid_filename,
                    tasks
                  ),
                  List[WorkResult](), attempts
                ),
                downloadconfig
              )
              log.debug("RabbitConsumer: sent a create message!")
              totalDemand -= 1
            case msg =>
              log.error("RabbitConsumer: received a RabbitMessage that cannot be cast to a ZooWork {}", msg)
          }
        } catch {
          case e: org.json4s.MappingException =>
            log.error("RabbitConsumer: parsing error -> {}", e.msg)
        }

    case Ack(n: Long) =>
      this.channel.basicAck(n, false)
      sender ! ConsumerResolution(true)
      log.info("RabbitConsumer: just acked {} successfully", n)

    case NAck(n: Long) =>
      this.channel.basicNack(n, false, true)
      sender ! NackResolution(true)
      log.warning("RabbitConsumer: just nacked {} successfully", n)

    case msg =>
      log.error("RabbitConsumer: received a message I cannot match against: {}", msg)
  }
}
