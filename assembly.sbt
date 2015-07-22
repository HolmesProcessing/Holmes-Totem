import AssemblyKeys._

assemblySettings

mergeStrategy in assembly <<= (mergeStrategy in assembly) { (old) =>
  {
    //case PathList("org", "apache", "commons-io", xs @ _*) => MergeStrategy.last
    //case x => old(x)
    case PathList("META-INF", "MANIFEST.MF") => MergeStrategy.discard
    case m if m.toLowerCase.matches("meta-inf/.*\\.sf$") => MergeStrategy.discard
    case "reference.conf" => MergeStrategy.concat
    case _ => MergeStrategy.first //this was originally last, which worked up till client/server mismatch issues
  }
}
