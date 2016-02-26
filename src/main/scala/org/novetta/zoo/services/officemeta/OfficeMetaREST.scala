package org.novetta.zoo.services.officemeta

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.novetta.zoo.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class OfficeMetaWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = OfficeMetaREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        OfficeMetaSuccess(true, JString(content), Arguments)

      case Left(StatusCode(500)) =>
        OfficeMetaFailure(false, JString("OfficeMeta service failed, check local logs"), Arguments)

      case Left(StatusCode(code)) =>
        OfficeMetaFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        OfficeMetaFailure(false, JString("Wildcard failure: " + something.toString), Arguments)

      })
    requestResult
  }
}


case class OfficeMetaSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "zipmeta.result.static.totem", WorkType: String = "ZIPMETA") extends WorkSuccess
case class OfficeMetaFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "ZIPMETA") extends WorkFailure


object OfficeMetaREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
