package org.holmesprocessing.totem.types

import org.holmesprocessing.totem.util.DownloadSettings

/**
 * Create() case class. Used between the ConsumerActor and the WorkGroup.
 * @param config: DownloadSettings => The configuration options for downloading an object
 * @param key: Long => The message key associated with this work.
 * @param primaryURI: String => The primary URL for downloading the target resource
 * @param secondaryURI: String => The secondary URL for downloading the target resource
 * @param value: WorkState => The state of the Job, and component work at time of creation
 *
 * @constructor Generate a Create message. This is used to initiate the creation of a WorkActor
 *
 */
case class Create(key: Long, download: Boolean, primaryURI: String, secondaryURI: String, tags: List[String], value: WorkState, config: DownloadSettings)

/**
 * Result case class. Used between the WorkActor and the ProducerActor
 * @param filename: String => The filename representing the target of this Job
 * @param result: WorkResult => The WorkResult representing the end state of the Job
 *
 * @constructor Generate a Result message. This is used to transmit results to the Producer and from there, to the queueing backbone
 *
 */
case class Result(filename: String, result: WorkResult)

/**
 * ResultPackage case class. A package of results for transmission. The various filehashes are used for secondary aggregation against
 * the target processing file, that information is lost due to the UUID usage in the temporary filestore.
 * @param filename: String => The filename representing the target of this Job
 * @param results: Iterable[WorkResult] => An Iterable representing the WorkResults to be transmitted
 * @param tags: List[String] => A list of tags for the results
 * @param MD5: String => MD5 hash of the target file.
 * @param SHA1: String => SHA1 hash of the target file.
 * @param SHA256: String => SHA256 hash of the target file.
 *
 * @constructor Generate a ResultPackage message. This is for multiple WorkResult transfers.
 *
 */
case class ResultPackage(filename: String, results: Iterable[WorkResult], tags: List[String], MD5: String, SHA1: String, SHA256: String)

object WorkState {
  def create(filename: String, hashfilename: String, workToDo: List[TaskedWork], results: List[WorkResult] = List[WorkResult](), attempts: Int): WorkState = {
    WorkState(filename, hashfilename, workToDo, 0, 0, results, attempts)
  }
}

/**
 * WorkState case class. A representation of the current state of a given Job. This can be used to merge Jobs, or transfer overall Job state.
 * @param filename: String => The filename representing the target of this Job.
 * @param hashfilename: String => The hashed filename representing the target of the Job.
 * @param workToDo: List[TaskedWork] => A list of all TaskedWork elements, which are the component Work elements
 * @param created: Int => The time this work was created.
 * @param lastEdited: Int => The last time this work had an altered state.
 * @param results: List[WorkResult] => A list of the WorkResults that have been generated.
 * @param attempts: Int => The number of times this Job has been attempted across all executors.

 * @constructor Generate a WorkState message.
 *
 */
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
