package org.holmesprocessing.totem.util

import java.security.MessageDigest
import com.typesafe.scalalogging.{Logger, LazyLogging}
import org.holmesprocessing.totem.types.{WorkState, WorkResult, TaskedWork}
import org.slf4j.LoggerFactory

case class DownloadSettings(download_directory: String, request_timeout: Int, connect_timeout: Int)

object DownloadMethods extends Instrumented with LazyLogging {
  val log = Logger(LoggerFactory.getLogger("name"))

  def MD5(s: Array[Byte]): String = {
    MessageDigest.getInstance("MD5").digest(s).map("%02X".format(_)).mkString
  }
  def SHA1(s: Array[Byte]): String = {
    MessageDigest.getInstance("SHA-1").digest(s).map("%02X".format(_)).mkString
  }
  def SHA256(s: Array[Byte]): String = {
    MessageDigest.getInstance("SHA-256").digest(s).map("%02X".format(_)).mkString
  }
}
