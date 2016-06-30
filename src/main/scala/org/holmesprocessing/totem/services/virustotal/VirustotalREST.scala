package org.holmesprocessing.totem.services.virustotal

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class VirustotalWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = VirustotalREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        VirustotalSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        VirustotalFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        VirustotalFailure(false, JString("VT service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        VirustotalFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        VirustotalFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class VirustotalSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "virustotal.result.static.totem", WorkType: String = "VIRUSTOTAL") extends WorkSuccess
case class VirustotalFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "VIRUSTOTAL") extends WorkFailure


object VirustotalREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
