package org.holmesprocessing.totem.services.asnmeta

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class ASNMetaWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = ASNMetaREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        ASNMetaSuccess(true, JString(content), Arguments)

      case Left(StatusCode(400)) =>
        ASNMetaFailure(false, JString("Address type is not global"), Arguments)

      case Left(StatusCode(404)) =>
        ASNMetaFailure(false, JString("Not found (malformed address?)"), Arguments)

      case Left(StatusCode(500)) =>
        ASNMetaFailure(false, JString("ASNMeta service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        ASNMetaFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        ASNMetaFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class ASNMetaSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "asnmeta.result.static.totem", WorkType: String = "ASNMETA") extends WorkSuccess
case class ASNMetaFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "ASNMETA") extends WorkFailure


object ASNMetaREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
