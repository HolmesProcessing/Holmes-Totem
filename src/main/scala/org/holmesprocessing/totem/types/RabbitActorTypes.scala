package org.holmesprocessing.totem.types

case class QueueSettings(queueName: String, routingKey: List[String], durable: Boolean, exclusive: Boolean, autodelete: Boolean)
case class ExchangeSettings(exchangeName: String, exchangeType: String, durable: Boolean)
case class HostSettings(host: String, port: Int, user: String, password: String, vhost: String)

case class Send(message: RMQSendMessage)
case class Ack(deliveryTag: Long)
case class NAck(deliveryTag: Long)
case class RMQSendMessage(body: Array[Byte], routingKey: String)

case class RabbitMessage(deliveryTag: Long, body: Array[Byte])
