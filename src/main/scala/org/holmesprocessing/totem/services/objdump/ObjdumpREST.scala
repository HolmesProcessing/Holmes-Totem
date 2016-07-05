package org.holmesprocessing.totem.services.objdump

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.holmesprocessing.totem.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class ObjdumpWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = ObjdumpREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        ObjdumpSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        ObjdumpFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        ObjdumpFailure(false, JString("Objdump service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        ObjdumpFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        ObjdumpFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class ObjdumpSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "objdump.result.static.totem", WorkType: String = "OBJDUMP") extends WorkSuccess
case class ObjdumpFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "OBJDUMP") extends WorkFailure


object ObjdumpREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
