package org.holmesprocessing.totem.util

import java.util.concurrent.TimeUnit

import akka.actor.Actor
import com.codahale.metrics.{ConsoleReporter, JmxReporter}
import com.codahale.metrics.json.MetricsModule
import com.fasterxml.jackson.databind.ObjectMapper
import nl.grons.metrics.scala.InstrumentedBuilder

object MetricService extends InstrumentedBuilder {

  //Create global metrics registry and JMX reporter
  val metricRegistry = new com.codahale.metrics.MetricRegistry()
  val reporter = JmxReporter.forRegistry(metricRegistry).build() //keeping you so that we have a JMX backup
  reporter.start()
  sys.addShutdownHook(reporter.stop())

  //Register some metrics
  metrics.gauge("totalMemory")(Runtime.getRuntime.totalMemory)
  metrics.gauge("usedMemory")(Runtime.getRuntime.totalMemory - Runtime.getRuntime.freeMemory)

  //Use "metrics-json" to serialize the registry
  private val mapper = new ObjectMapper().registerModule(new MetricsModule(TimeUnit.SECONDS, TimeUnit.MILLISECONDS, false))

  def metricRegistryJsonString = mapper.writeValueAsString(metricRegistry)

}

trait Instrumented extends InstrumentedBuilder {

  val metricRegistry = MetricService.metricRegistry

}

//TODO: Build this out and remove metrics-scala since its ActorMetrics API is screwed up
trait MonitoredActor extends Actor with Instrumented {

  val timer = metrics.timer("receive")

  final def receive =
    timer.timePF {
      monitoredReceive //TODO: use orElse to update an unhandled message metric
    }

  def monitoredReceive: Actor.Receive
}
