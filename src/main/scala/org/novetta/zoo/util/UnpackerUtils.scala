package org.novetta.zoo.util

import java.io.File
import java.net.URL
import java.util.zip.ZipInputStream
import org.apache.commons.io.FileUtils

object UnpackerUtils {
  def unpack(resourcePath: String, targetPath: String) = {
    /**
    URL url = MyClass.class.getResource("resources/");
    if (url == null) {
      // error - missing folder
    } else {
      File dir = new File(url.toURI());
      for (File nextFile : dir.listFiles()) {
        // Do something with nextFile
      }
    }
      **/
    val jar = getClass.getProtectionDomain.getCodeSource.getLocation
    val zip: ZipInputStream = new ZipInputStream(jar.openStream())
    println(zip.getNextEntry.getName)
    val inputUrl: URL = getClass.getResource(resourcePath)
    FileUtils.copyURLToFile(inputUrl, new File("/tmp/python/"))

    println(inputUrl)
    val resource = new File(inputUrl.toString)
    val listResource = resource.listFiles()
    println(listResource)
    try {
      val apps: File = new File(inputUrl.getPath)
      val dest: File = new File(targetPath)
      if (apps.isDirectory) {
        apps.listFiles.foreach(fi =>
          System.out.println(fi.getAbsolutePath)
        )
      }
    } catch {
      case _: Throwable =>
        val inputUrl: URL = getClass.getResource(resourcePath)
        val dest: File = new File(targetPath)
        FileUtils.copyURLToFile(inputUrl, dest)
    }
  }
}
