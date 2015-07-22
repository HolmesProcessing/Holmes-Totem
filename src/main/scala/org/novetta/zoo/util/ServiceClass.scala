package org.novetta.zoo.util

import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.slf4j.LoggerFactory
import scala.collection.JavaConversions._
import scala.util.Random

class ServiceClass(conf: Config) {
  val keys = conf.getObject("zoo.enrichers").keySet()
  val en = conf.getObject("zoo.enrichers").toConfig
  val services = keys.map(key =>
    (key, Random.shuffle(en.getStringList(s"$key.uri").toList))
  ).toMap[String, List[String]]
  val log = Logger(LoggerFactory.getLogger("name"))

  def GeneratePartial(work: String): String = {
    work match {
      case "FILE_METADATA" => Random.shuffle(services.getOrElse("metadata", List())).head
      case "HASHES" => Random.shuffle(services.getOrElse("hashes", List())).head
      case "PEINFO" => Random.shuffle(services.getOrElse("peinfo", List())).head
      case "VTSAMPLE" => Random.shuffle(services.getOrElse("vtsample", List())).head
      case "YARA" => Random.shuffle(services.getOrElse("yara", List())).head

    }
  }
}