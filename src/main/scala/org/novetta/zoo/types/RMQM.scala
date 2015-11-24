package org.novetta.zoo.types

import org.json4s._
import org.json4s.jackson.JsonMethods._


case class ZooWork(primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], attempts: Int) {

  /**
   * Helper function to manage download callbacks. This attempts a download, moves to the fallback URI if the first one fails
   * and reports the overall result to the originating actor.
   *
   * @return Unit. Returns are via callback messages.
   * @param sender: a String: The ActorRef that we will reply to.
   * @param id: a Long: The ID of the message in question.
   * @param filename: a String: The name of the file we are downloading.
   * @param svc1: a Req: The first URI to try.
   * @param svc2: a Req: The fallback URI.
   * @param attempts: an Int: Number of times this download has been attempted.
   */
  def +(that: WorkFailure): ZooWork = {
    val newtasks = this.tasks + (that.WorkType -> that.Arguments)
    new ZooWork(
      primaryURI = this.primaryURI,
      secondaryURI = this.secondaryURI,
      filename = this.filename,
      tasks = newtasks,
      attempts = this.attempts
    )
  }
}

//the abstract class for anyone who wants to implement their own stuff. Need to ensure data flow supports this. See RabbitSender
abstract class ZooWorkC(primaryURI: String, secondaryURI: String,
                        filename: String, tasks: Map[String, List[String]], attempts: Int) {
  def +(that: WorkFailure): (ZooWorkC)
}

case class CritsData(CritsURL: Option[String] = None, AnalysisId: Option[String] = None,
                     ObjectType: Option[String] = None, ObjectId: Option[String] = None,
                     Username: Option[String] = None, ApiKey: Option[String] = None,
                     MD5: Option[String] = None, Source: Option[String] = None
                    )

case class CritsWork(primaryURI: String, secondaryURI: String, filename: String,
                     tasks: Map[String, List[String]], attempts: Int, critsMetadata: CritsData) extends
ZooWorkC(primaryURI, secondaryURI, filename,
  tasks, attempts) {
  def +(that: WorkFailure): CritsWork = {
    val newtasks = this.tasks + (that.WorkType -> that.Arguments)
    new CritsWork(
      this.primaryURI,
      this.secondaryURI,
      this.filename,
      newtasks,
      this.attempts,
      this.critsMetadata
    )
  }
}
/*
val datatest = CritsData(Some("someurl"), Some("someid"))
val critsWorkSecond = CritsWork("http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5",
  "http://127.0.0.1:9900/000a887477d86792d38bac9bbe786ed5",
  "000a887477d86792d38bac9bbe786ed5",
  Map[String, List[String]](
    "FILE_METADATA" -> List[String](), "YARA" -> List[String](), "PEINFO" -> List[String]()), 0, datatest)
val json = (
  ("primaryURI" -> critsWorkSecond.primaryURI) ~
    ("secondaryURI" -> critsWorkSecond.secondaryURI) ~
    ("filename" -> critsWorkSecond.filename) ~
    ("tasks" -> critsWorkSecond.tasks) ~
    ("attempts" -> critsWorkSecond.attempts) ~
    ("critsMetadata" ->
      ("AnalysisID" -> critsWorkSecond.critsMetadata.AnalysisId) ~
      ("ApiKey" -> critsWorkSecond.critsMetadata.ApiKey)
      )
  )
 */

object Parsers {
  type Parser[T] = (Array[Byte] => T)
  implicit val formats = DefaultFormats
  /**
  def jsonToChild:Parser[Child] = {
    json =>
      val result: Child = parse(new String(json)).extract[Child]
      result
  }
  **/
  /**
   * Helper function to manage download callbacks. This attempts a download, moves to the fallback URI if the first one fails
   * and reports the overall result to the originating actor.
   *
   * @return Unit. Returns are via callback messages.
   * @param sender: a String: The ActorRef that we will reply to.
   * @param id: a Long: The ID of the message in question.
   * @param filename: a String: The name of the file we are downloading.
   * @param svc1: a Req: The first URI to try.
   * @param svc2: a Req: The fallback URI.
   * @param attempts: an Int: Number of times this download has been attempted.
   */
  def parseJ[T: Manifest](data: Array[Byte]): T = {
    val result: T = parse(new String(data)).extract[T]
    result
  }
}
