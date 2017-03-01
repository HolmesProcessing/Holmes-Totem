package org.holmesprocessing.totem.services.pdfparse

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class pdfparseWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = pdfparseREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        pdfparseSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        pdfparseFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        pdfparseFailure(false, JString("Objdump service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        pdfparseFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        pdfparseFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class pdfparseSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "pdfparse.result.static.totem", WorkType: String = "PDFPARSE") extends WorkSuccess
case class pdfparseFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "PDFPARSE") extends WorkFailure


object pdfparseREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
