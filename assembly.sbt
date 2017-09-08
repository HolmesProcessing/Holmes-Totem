assemblyMergeStrategy in assembly := {
	case PathList("META-INF", "MANIFEST.MF") => MergeStrategy.discard   // not needed to keep these, discard
	case "reference.conf" => MergeStrategy.concat                       // concat all akka reference.conf files 
	case _ => MergeStrategy.first                                       // important to keep LICENSE files in place
}
