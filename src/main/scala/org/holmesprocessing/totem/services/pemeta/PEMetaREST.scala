package org.holmesprocessing.totem.services.pemeta

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class PEMetaWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = PEMetaREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        PEMetaSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        PEMetaFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        PEMetaFailure(false, JString("PEInfoservice failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        PEMetaFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        PEMetaFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class PEMetaSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "pemeta.result.static.totem", WorkType: String = "PEMETA") extends WorkSuccess
case class PEMetaFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "PEMETA") extends WorkFailure


object PEMetaREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
