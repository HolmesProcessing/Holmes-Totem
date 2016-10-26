package org.holmesprocessing.totem.services.richheader

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class RichHeaderWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = RichHeaderREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        RichHeaderSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        RichHeaderFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        RichHeaderFailure(false, JString("RichHeader service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        RichHeaderFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        RichHeaderFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class RichHeaderSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "richheader.result.static.totem", WorkType: String = "RICHHEADER") extends WorkSuccess
case class RichHeaderFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "RICHHEADER") extends WorkFailure


object RichHeaderREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
