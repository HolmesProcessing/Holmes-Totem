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

      case Left(StatusCode(400)) =>
        PassiveTotalFailure(false, JString("Malformed Request"), Arguments)

      case Left(StatusCode(401)) =>
        PassiveTotalFailure(false, JString("Invalid Username or API-Key for PassiveTotal"), Arguments)

      case Left(StatusCode(402)) =>
        PassiveTotalFailure(false, JString("PassiveTotal Quota Reached"), Arguments)

      case Left(StatusCode(404)) =>
        PassiveTotalFailure(false, JString("Not found (malformed address?)"), Arguments)

      case Left(StatusCode(422)) =>
        PassiveTotalFailure(false, JString("Unknown Object Type"), Arguments)

      case Left(StatusCode(500)) =>
        PassiveTotalFailure(false, JString("PassiveTotal service failed, check local logs"), Arguments)

      case Left(StatusCode(502)) =>
        PassiveTotalFailure(false, JString("PassiveTotal API Unreachable, check local logs"), Arguments)

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
