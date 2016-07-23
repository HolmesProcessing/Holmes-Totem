package org.holmesprocessing.totem.types

import org.json4s._
import org.json4s.jackson.JsonMethods._


case class ZooWork(download: Boolean, primaryURI: String, secondaryURI: String, filename: String, tasks: Map[String, List[String]], tags: List[String], attempts: Int) {

  def +(that: WorkFailure): ZooWork = {
    val newtasks = this.tasks + (that.WorkType -> that.Arguments)
    new ZooWork(
      download = this.download,
      primaryURI = this.primaryURI,
      secondaryURI = this.secondaryURI,
      filename = this.filename,
      tasks = newtasks,
      tags = this.tags,
      attempts = this.attempts
    )
  }
}

object Parsers {
  type Parser[T] = (Array[Byte] => T)
  implicit val formats = DefaultFormats

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
