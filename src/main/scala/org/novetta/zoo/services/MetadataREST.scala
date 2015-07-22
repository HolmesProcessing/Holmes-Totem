package org.novetta.zoo.services

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JInt, JString, JValue}
import org.novetta.zoo.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}

import scala.collection.mutable.StringBuilder
import collection.mutable

/**
 * MetadataWork case class. Holds the tasking and worker path appropriate for this TaskedWork
 * @param key: Long => The message key associated with this work
 * @param filename: String => The filename that refers to this work's instance on disk
 * @param WorkType: String => The type of work that needs to be performed
 * @param Worker: String => The Path that will operate on this work
 *
 * @constructor Create a new MetadataWork.
 *
 */

case class MetadataWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = { //implicit execution context? Currying?
    val uri = MetadataREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        MetadataSuccess(true, JString(content), Arguments) //should we parse content? yes. we should convert to a map structure?
      case Left(StatusCode(404)) =>
        MetadataFailure(false, JString("Not found"), Arguments) //should our key here be a boolean for success, or failure at the coordinator level?
      case Left(StatusCode(code)) =>
        MetadataFailure(false, JString("Some other code: " + code.toString), Arguments)
      case Left(something) =>
        MetadataFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}

/**
 * MetadataResult case class. Holds the tasking and worker path appropriate for this TaskedWork
 * @param status: Boolean => If this work completed successfully. We are not discriminating between a failure on the service, or a failure in the coordinator
 * @param data: String => The results of the worker. All workers MUST return some sane JSON element. Handling of this JSON element
 *      is to be done at DB ingest time.
 * @constructor Create a new MetadataResult.
 *
 */
case class MetadataSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "metadata.result.static.zoo", WorkType: String = "FILE_METADATA") extends WorkSuccess //want to add a time of completion? might also need to change ID to the original taskedwork
case class MetadataFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "FILE_METADATA") extends WorkFailure //want to add a time of completion? might also need to change ID to the original taskedwork

object MetadataREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
