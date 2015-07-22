package org.novetta.zoo.types

case class Create(key: Long, primaryURI: String, secondaryURI: String, value: WorkState)

case class Result(filename: String, result: WorkResult)
case class ResultPackage(filename: String, results: Iterable[WorkResult], MD5: String, SHA1: String, SHA256: String)

object WorkState {
  def create(filename: String, hashfilename: String, workToDo: List[TaskedWork], results: List[WorkResult] = List[WorkResult](), attempts: Int): WorkState = {
    WorkState(filename, hashfilename, workToDo, 0, 0, results, attempts)
  }
}

case class WorkState(
                      filename: String,
                      hashfilename: String,
                      workToDo: List[TaskedWork],
                      created: Int = 0,
                      lastEdited: Int = 0,
                      results: List[WorkResult] = List[WorkResult](),
                      attempts: Int = 0
                      ) {
  def isComplete: Boolean = {
    workToDo.size == results.size
  }
  def +(that: WorkResult): WorkState = {
    new WorkState(
      filename = this.filename,
      hashfilename = this.hashfilename,
      workToDo = this.workToDo,
      created = this.created,
      lastEdited = 1,
      results = this.results :+ that,
      attempts = this.attempts
    )
  }
}
