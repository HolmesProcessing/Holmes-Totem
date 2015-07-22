package org.novetta.zoo.actors

import akka.actor._
import com.rabbitmq.client._
import com.typesafe.config.Config
import org.novetta.zoo.types._
import org.novetta.zoo.util.MonitoredActor
/**
 * @constructor This is the companion object to the class. Simplifies Props() nonsense.
 */
object WorkGroup {
  def props(): Props = {
    Props(new WorkGroup() )
  }}

/**
 * This actor represents the manager for all WorkActors. This is currently a manager actor, whose purpose is to make scaling,
 * deathwatch, and load balancing easier across an arbitrarily complex actor system. It is also the interface between WorkActors
 * and their source Consumer. In short, this is a "Best Practice" actor.
 *
 * Something like:
 * {{{
 *   val myWorker: ActorRef = context.actorOf(WorkActor.props(), "group")
 * }}}
 * is the preferred way to create this actor.
 *
 * The following is a listing of the message types that this Actor explicitly handles, and a brief discussion of their purpose.
 * {{{
 *   case Create(channel: Channel, key: Long, primaryURI: String, secondaryURI: String, value: WorkState) => {
 *     Create a new WorkActor, should one not exist already, based on the Key provided, and add it to the watch list.
 *   }
 *   case t: Get => {
 *     Pass along a Get message to the parent consumer.
 *   }
 *   case Terminated(t: ActorRef) => {
 *     Notification for when a child actor terminates.
 *   }
 *
 * }}}
 * @constructor Create a new WorkGroup which manages and watches the WorkActors. While not strictly needed, this is helpful for failure recovery and remoting should it be needed.
 *
 */

class WorkGroup extends Actor with ActorLogging with MonitoredActor {

  def monitoredReceive = {
    case Create(key: Long, primaryURI: String, secondaryURI: String, value: WorkState) =>
      val child = context.child(key.toString).getOrElse({
        log.info(s"Instantiating a new actor for message: {}", key)
        context.watch(
          context.actorOf(
            WorkActor.props(key, value.filename, value.hashfilename, primaryURI,secondaryURI, value.workToDo, value.attempts), key.toString
          )
        )

      })
    case t: Ack =>
      log.info("Got an Ack from {}, moving up the chain", sender())
      context.parent.tell(t, sender())

    case t: NAck =>
      log.info("Got an NAck from {}, moving up the chain", sender())
      context.parent.tell(t, sender())

    case Terminated(t: ActorRef) =>
      log.info("child {} terminated", t)
    case msg =>
      log.info("Got something we didn't understand {}", msg)
  }
}
