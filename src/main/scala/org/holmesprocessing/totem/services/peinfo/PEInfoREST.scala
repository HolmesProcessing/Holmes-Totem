package org.holmesprocessing.totem.services.peinfo

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class PEInfoWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = PEInfoREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        PEInfoSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        PEInfoFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        PEInfoFailure(false, JString("PEInfo service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        PEInfoFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        PEInfoFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class PEInfoSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "peinfo.result.static.totem", WorkType: String = "PEINFO") extends WorkSuccess
case class PEInfoFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "PEINFO") extends WorkFailure


object PEInfoREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
