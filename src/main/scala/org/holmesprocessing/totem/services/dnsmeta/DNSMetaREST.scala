package org.holmesprocessing.totem.services.dnsmeta

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class DNSMetaWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = DNSMetaREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        DNSMetaSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        DNSMetaFailure(false, JString("Not found (malformed address?)"), Arguments)

      case Left(StatusCode(500)) =>
        DNSMetaFailure(false, JString("DNSMeta service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        DNSMetaFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        DNSMetaFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class DNSMetaSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "dnsmeta.result.static.totem", WorkType: String = "DNSMETA") extends WorkSuccess
case class DNSMetaFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "DNSMETA") extends WorkFailure


object DNSMetaREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
