package org.holmesprocessing.totem.services.gogadget

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class GoGadgetWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = GoGadgetREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        GoGadgetSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        GoGadgetFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        GoGadgetFailure(false, JString("Objdump service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        GoGadgetFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        GoGadgetFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class GoGadgetSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "gogadget.result.static.totem", WorkType: String = "GOGADGET") extends WorkSuccess
case class GoGadgetFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "GOGADGET") extends WorkFailure


object GoGadgetREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
