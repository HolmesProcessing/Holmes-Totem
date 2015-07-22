package org.novetta.zoo.actors

/**
 * This actor will register itself to consume messages from the RabbitMQ server.
 *
 */

import java.util.UUID

import akka.actor._
import com.codahale.metrics.Histogram
import com.rabbitmq.client._
import org.json4s._
import org.json4s.jackson.JsonMethods._
import org.novetta.zoo.types._
import org.novetta.zoo.util.MonitoredActor
import scala.concurrent.duration.{FiniteDuration, _}
import org.novetta.zoo.types.WorkEncoding
/**
 * @constructor This is the companion object to the RabbitConsumerActor class.
 */
object RabbitConsumerActor {
  def props[T: Manifest](host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, servicelist: WorkEncoding, decoder: Parsers.Parser[T]): Props = {
    Props(new RabbitConsumerActor(host, exchange, queue, servicelist, decoder) )
  }
}
/**
 * This actor will register itself to consume messages from the RabbitMQ server. This gets a dedicated thread, and a
 * new consumer should be created for each queue that we need to consume from. This is a cleaner design overall. Should
 * multiple queues be needed, their dispatcher will get a dedicated thread, and the actors themselves, as they are lightweight
 * processes, will share it.
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
 *   case msg: RabbitMessage => {
 *     When a new RMQ message is returned from the callback, take it, attempt to parse the ZooWork JSON out of it, and pass to the
 *     WorkGroup actor for handling. Decrement totalDemand, so that we do not attempt to consume the world.
 *   }
 *   case Get(n: Int) => {
 *     Increment totalDemand by n.
 *   }
 *
 * }}}
 *
 * @constructor Create a new RabbitConsumerActor, which consumes JSON formatted RabbitMessages from RMQ, transforms them
 *             into objects of type [T], and emits those objects to the state actor groups.
 * @param host: a HostSettings object, responsible for holding the server configuration to use.
 * @param exchange: an ExchangeSettings object, holds the exchange configuration.
 * @param queue: a QueueSettings object, holds queue configuration.
 * @param decoder: a Parsers.Parser[T], which is responsible for transforming the JSON data into a Scala object.
 */

class RabbitConsumerActor[T: Manifest](host: HostSettings, exchange: ExchangeSettings, queue: QueueSettings, servicelist: WorkEncoding, decoder: Parsers.Parser[T]) extends Actor with ActorLogging with MonitoredActor {
  implicit val formats = DefaultFormats
  var WorkGroupActor: ActorRef =_
  var totalDemand = 0
  var channel: Channel =_

  val resultCounts: Histogram = metricRegistry.histogram(classOf[RabbitConsumerActor[ZooWork]].getName + "ack-map-counts")
  resultCounts.update(totalDemand)

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
  this.channel.queueBind(queue.queueName, exchange.exchangeName, queue.routingKey)

  def consumeOne() = {
    val autoAck: Boolean = false
    val response: GetResponse = channel.basicGet(queue.queueName, autoAck)
    if (response == null) {
      // No message retrieved. Do nothing.
    } else {
      val props: AMQP.BasicProperties = response.getProps
      val body: Array[Byte] = response.getBody
      val deliveryTag: Long = response.getEnvelope.getDeliveryTag
      self ! new RabbitMessage(deliveryTag, body)//, channel)
    }
  }

  channel.basicQos(3)  //config me

  val consumer = new DefaultConsumer(this.channel) {
    override def handleDelivery(
                                 consumerTag: String,
                                 envelope: Envelope,
                                 properties: AMQP.BasicProperties,
                                 body: Array[Byte]) = {
      log.info("handle delivery {}, {}, {}", envelope.getDeliveryTag, envelope.isRedeliver, channel.hashCode())

      self ! new RabbitMessage(envelope.getDeliveryTag, body)
    }
  }
  this.channel.basicConsume(queue.queueName, false, consumer)
  def monitoredReceive = {
    case RabbitMessage(deliveryTag: Long, body: Array[Byte]) => //, chan: Channel) =>
        log.info("totaldemand is good, and we got a rabbit message")

        try {
          parse(new String(body)).extract[T] match {
            case ZooWork(primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], attempts: Int) =>
              log.info("Created a ZooWork, {}", filename)
              val uuid_filename: String = UUID.randomUUID().toString
              WorkGroupActor ! Create(
                deliveryTag,
                primaryURI,
                secondaryURI,
                WorkState.create(
                  uuid_filename,
                  filename,
                  servicelist.enumerateWork(
                    deliveryTag,
                    uuid_filename,
                    tasks
                  ),
                  List[WorkResult](), attempts
                )
              )
              log.info("We sent a create message!")
              totalDemand -= 1
            case msg =>
              log.error("NOT SURE WHAT WE GOT {}", msg)
          }
        } catch {
          case e: org.json4s.MappingException =>
            log.info(e.msg)
        }

    case Ack(n: Long) =>
      log.info("channel open? {}", this.channel.isOpen)
      log.info("channel closed because {}", this.channel.getCloseReason)
      this.channel.basicAck(n, false)
      sender ! ConsumerResolution(true)
      log.info("just acked {} successfully", n)

    case NAck(n: Long) =>
      log.info("channel open? {}", this.channel.isOpen)
      log.info("channel closed because {}", this.channel.getCloseReason)
      this.channel.basicNack(n, false, true)
      sender ! NackResolution(true)
      log.info("just nacked {} successfully", n)

    case msg =>
      log.info("Don't know what this is, ignoring. {}", msg)
  }
}