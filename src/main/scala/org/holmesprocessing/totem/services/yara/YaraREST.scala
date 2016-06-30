package org.holmesprocessing.totem.services.yara

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable

/**
 * YaraWork case class. Performs the actual enrichment and data parsing. Returns a series of
 * @param key: Long => The message key associated with this work.
 * @param filename: String => The filename that refers to this work's target instance on disk.
 * @param TimeoutMillis: Int => The timeout for this job, assuming it is not already set by the implicit HTTP client
 * @param WorkType: String => The type of work that needs to be performed.
 * @param Worker: String => The Path that will operate on this work. This is generally an external URI, but can be a local resource
 *              or actor as well.
 * @param Arguments: List[String] => A list of secondary arguments that are associated with this particular work element.
 *
 * @constructor Create a new YaraWork.
 *
 */

case class YaraWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    // Parameters will be send via Post so we dont need the builder here
    //val uri = YaraREST.constructURL(Worker, filename, Arguments)
    var req = url(Worker+filename)
    if(!Arguments.isEmpty){
      // since the Arguments are passed as list at the moment
      // (this will be changed later) we assume that the
      // first Argument is the base64 encoded AND compiled
      // yara rule we want to pass to the service.
      val params = Map("custom_rule" -> Arguments.head)
      req = req <<(params)  
    }

    val requestResult = myHttp(req OK as.String)
      .either
      .map({
      case Right(content) =>
        YaraSuccess(true, JString(content), Arguments) //should we parse content? yes. we should convert to a map structure?
      case Left(StatusCode(404)) =>
        YaraFailure(false, JString("Not found"), Arguments) //should our key here be a boolean for success, or failure at the coordinator level?
      case Left(StatusCode(code)) =>
        YaraFailure(false, JString("Some other code: " + code.toString), Arguments)
      case Left(something) =>
        YaraFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}

/**
 * YaraResult case class. Holds the tasking and worker path appropriate for this TaskedWork
 * @param status: Boolean => If this work completed successfully. We are not discriminating between a failure on the service, or a failure in the coordinator
 * @param data: String => The results of the worker. All workers MUST return some sane JSON element. Handling of this JSON element
 *      is to be done at DB ingest time.
 * @constructor Create a new YaraResult.
 *
 */
case class YaraSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "yara.result.static.totem", WorkType: String = "YARA") extends WorkSuccess //want to add a time of completion? might also need to change ID to the original taskedwork
case class YaraFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "YARA") extends WorkFailure //want to add a time of completion? might also need to change ID to the original taskedwork

object YaraREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
