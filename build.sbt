name := "totem"

version := "0.5.0"

scalaVersion := "2.11.4" //was 2.10.3

resolvers += "Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"

libraryDependencies += "com.typesafe.akka" %% "akka-actor" % "2.3.7"

libraryDependencies += "com.rabbitmq" % "amqp-client" % "3.4.2"

libraryDependencies += "org.json4s" %% "json4s-jackson" % "3.2.11"

libraryDependencies += "joda-time" % "joda-time" % "2.6"

libraryDependencies += "org.joda" % "joda-convert" % "1.7"

libraryDependencies += "net.databinder.dispatch" %% "dispatch-core" % "0.11.3"

libraryDependencies += "commons-io" % "commons-io" % "2.4"

libraryDependencies += "nl.grons" %% "metrics-scala" % "3.3.0_a2.3"

libraryDependencies += "io.dropwizard.metrics" % "metrics-json" % "3.1.0"

libraryDependencies += "com.typesafe.scala-logging" %% "scala-logging" % "3.1.0"

libraryDependencies += "com.typesafe" % "config" % "1.2.1"

libraryDependencies += "com.typesafe.akka" %% "akka-testkit" % "2.3.7"

libraryDependencies += "org.scalatest" % "scalatest_2.11" % "2.2.1" % "test"
