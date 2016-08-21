package org.holmesprocessing.totem.services.passivetotal

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class PassiveTotalWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = PassiveTotalREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        PassiveTotalSuccess(true, JString(content), Arguments)

      case Left(something) =>
        PassiveTotalFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class PassiveTotalSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "passivetotal.result.static.totem", WorkType: String = "PASSIVETOTAL") extends WorkSuccess
case class PassiveTotalFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "PASSIVETOTAL") extends WorkFailure


object PassiveTotalREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
