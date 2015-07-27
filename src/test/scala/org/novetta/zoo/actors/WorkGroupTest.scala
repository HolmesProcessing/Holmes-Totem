package org.novetta.zoo.actors

import org.scalatest.BeforeAndAfterAll
import org.scalatest.MustMatchers
import org.scalatest.WordSpecLike
import akka.actor.ActorSystem
import akka.testkit.TestActorRef
import akka.testkit.TestKit
import akka.testkit.EventFilter
import com.typesafe.config.ConfigFactory

//class ExampleSpec extends FlatSpec with Matchers
class WorkGroupTest extends TestKit(
  ActorSystem("TotemTestActorSystem", ConfigFactory.parseString("""akka.loggers = ["akka.testkit.TestEventListener"]"""))
) with WordSpecLike with MustMatchers with BeforeAndAfterAll {

  "A WorkGroupActor" must {
    val WorkGroupRef = TestActorRef(new WorkGroup())
    "log a message when it gets a message it does not understand" in {

      EventFilter.info(pattern = "WorkGroup has received a message *", occurrences = 1) intercept {
        WorkGroupRef ! "A string! This shouldn't be parsable."
      }

    }
  }

}