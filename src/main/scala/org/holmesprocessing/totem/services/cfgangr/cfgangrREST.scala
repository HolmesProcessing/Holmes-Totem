package org.holmesprocessing.totem.services.cfgangr

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class cfgAngrWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = cfgangrREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        cfgAngrSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        cfgAngrFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        cfgAngrFailure(false, JString("Objdump service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        cfgAngrFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        cfgAngrFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class cfgAngrSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "cfgangr.result.static.totem", WorkType: String = "cfgangr") extends WorkSuccess
case class cfgAngrFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "cfgangr") extends WorkFailure


object cfgangrREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
