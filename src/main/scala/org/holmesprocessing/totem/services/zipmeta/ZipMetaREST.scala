package org.holmesprocessing.totem.services.zipmeta

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class ZipMetaWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = ZipMetaREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        ZipMetaSuccess(true, JString(content), Arguments)

      case Left(StatusCode(400)) =>
        ZipMetaFailure(false, JString("Bad request"), Arguments)

      case Left(StatusCode(404)) =>
        ZipMetaFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        ZipMetaFailure(false, JString("ZipMeta service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        ZipMetaFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        ZipMetaFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class ZipMetaSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "zipmeta.result.static.totem", WorkType: String = "ZIPMETA") extends WorkSuccess
case class ZipMetaFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "ZIPMETA") extends WorkFailure


object ZipMetaREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
