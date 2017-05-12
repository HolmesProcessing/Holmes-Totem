package org.holmesprocessing.totem.services.cfg

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class cfgWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = cfgREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        cfgSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        cfgFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        cfgFailure(false, JString("Objdump service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        cfgFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        cfgFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class cfgSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "cfg.result.static.totem", WorkType: String = "cfg") extends WorkSuccess
case class cfgFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "cfg") extends WorkFailure


object cfgREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
