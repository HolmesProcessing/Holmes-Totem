package org.holmesprocessing.totem.services.shodan

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class ShodanWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = ShodanREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        ShodanSuccess(true, JString(content), Arguments)

      case Left(StatusCode(401)) =>
        ShodanFailure(false, JString("Invalid IP"), Arguments)

      case Left(StatusCode(404)) =>
        ShodanFailure(false, JString("API has no information available"), Arguments)

      case Left(StatusCode(500)) =>
        ShodanFailure(false, JString("Shodan service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        ShodanFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        ShodanFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class ShodanSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "shodan.result.static.totem", WorkType: String = "SHODAN") extends WorkSuccess
case class ShodanFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "SHODAN") extends WorkFailure


object ShodanREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
