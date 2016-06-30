package org.holmesprocessing.totem.actors
/*
import java.util.UUID

import akka.actor.{Actor, Props, ActorSystem}
import akka.testkit.{EventFilter, TestActorRef, TestKit}
import com.typesafe.config.ConfigFactory
import org.joda.time.DateTime
import org.holmesprocessing.totem.services.MetadataWork
import org.holmesprocessing.totem.types.{Conflict, TaskedWork, ZooWork}
import org.scalatest.{BeforeAndAfterAll, MustMatchers, WordSpecLike}

class WorkActorTest extends TestKit(
  ActorSystem("TotemTestActorSystem", ConfigFactory.parseString("""akka.loggers = ["akka.testkit.TestEventListener"]"""))
) with WordSpecLike with MustMatchers with BeforeAndAfterAll {

  //val zooworkSecond = ZooWork("http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5", "http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5",
  //  "000a887477d86792d38bac9bbe786ed5", Map[String, List[String]]("FILE_METADATA" -> List[String](), "YARA" -> List[String](), "PEINFO" -> List[String]()), 0)
  val goodTasks = List[TaskedWork](MetadataWork(1, uuid_name, 60, "FILE_METADATA", "http://127.0.0.1:7701/metadata/", List[String]("")))
  val uuid_name = UUID.randomUUID().toString
  //val goodActor = goodActorRef.underlyingActor

  "A Good WorkActor" must {


    "log a message when it successfully downloads a file on creation" in {
      EventFilter.info(pattern = "Successfully downloaded *", occurrences = 1) intercept {
        val goodActorRef = TestActorRef[WorkActor](Props(new WorkActor(1, uuid_name, "000a887477d86792d38bac9bbe786ed5",
          "http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5", "http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5", goodTasks, 0))
        )
      }
    }
    "log a message when it gets a message it does not understand" in {
      EventFilter.info(pattern = "WorkActor has received a message  *", occurrences = 1) intercept {
        goodActorRef ! "A string! This shouldn't be parsable."
      }
    }
  }
  "Any WorkActor" must {
    "Be able to compare timestamps" in {
      val goodActor = goodActorRef.underlyingActor
      assert(goodActor.timeDelta(Some(goodActor.created), DateTime.now()).getMillis > 0)
    }
    "Respond properly when Timestamps work poorly" in {
      val goodActor = goodActorRef.underlyingActor
      assert(goodActor.timeDelta(None, DateTime.now()).getMillis == 0)
    }
  }
}
*/
