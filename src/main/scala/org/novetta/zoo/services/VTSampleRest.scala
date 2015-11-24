package org.novetta.zoo.services

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.novetta.zoo.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class VTSampleWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = VTSampleREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        VTSampleSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        VTSampleFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        VTSampleFailure(false, JString("VT service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        VTSampleFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        VTSampleFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class VTSampleSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "vtsample.result.static.totem", WorkType: String = "VTSAMPLE") extends WorkSuccess
case class VTSampleFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "VTSAMPLE") extends WorkFailure


object VTSampleREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}

/**
 * README
 *
 * This service is designed to be used with the following Holmes service
 * running on the same machine as the Holmes-Totem instance. You can
 * currently get the service here altough the URL will most likely change
 * in the future:
 *
 * https://github.com/cynexit/Holmes-Totem-Service-VTSample/
 *
 * Please also check the README.md of the service.
 * 
 *
 * To enable this service add the following to your driver.scala:
 * 
 * Imports:
 * import org.novetta.zoo.services.{VTSampleSuccess, VTSampleWork}
 * 
 * TotemicEncoding->GeneratePartial:
 * case "VTSAMPLE" => Random.shuffle(services.getOrElse("vtsample", List())).head
 *
 * TotemicEncoding->enumerateWork:
 * case ("VTSample", li: List[String]) =>
 *   VTSampleWork(key, filename, 60, "VTSample", GeneratePartial("VTSample"), li)
 *
 * TotemicEncoding->workRoutingKey:
 * case x: VTSampleSuccess => "vtsample.result.static.zoo"
 *
 *
 * Also add this to the enrichers in your totem.conf
 *
 * vtsample {
 *   uri = ["http://127.0.0.1:7710/"]
 *   resultRoutingKey = "vtsample.result.static.totem"
 * }
 *
 */
 