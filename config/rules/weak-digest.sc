// Joern query: MD5/SHA-1 MessageDigest use (CWE-328), reported as SARIF.
// Inputs come from the environment because the Windows launcher splits --param on "=".
import java.nio.file.{Files, Paths}

val graph = sys.env("JOERN_CPG")
val report = sys.env("JOERN_REPORT")
// enhance=false: the query only needs parser-level properties (call name/args/line);
// the default overlay passes crash on large CPGs and are slow.
importCpg(graph, enhance = false)
val results = cpg.call.nameExact("getInstance")
  .filter(_.methodFullName.startsWith("java.security.MessageDigest.getInstance"))
  .filter(call => Set("\"MD5\"", "\"SHA-1\"").contains(call.argument(1).code))
  .l.flatMap { call =>
    call.lineNumber.map { line =>
      val location = ujson.Obj("artifactLocation" -> ujson.Obj("uri" -> call.location.filename),
                               "region" -> ujson.Obj("startLine" -> line.toInt))
      ujson.Obj("ruleId" -> "weak-digest", "level" -> "warning",
                "message" -> ujson.Obj("text" -> "Weak message digest"),
                "locations" -> ujson.Arr(ujson.Obj("physicalLocation" -> location)))
    }
  }
val rule = ujson.Obj("id" -> "weak-digest", "properties" -> ujson.Obj("tags" -> ujson.Arr("CWE-328")))
val driver = ujson.Obj("name" -> "joern", "rules" -> ujson.Arr(rule))
val run = ujson.Obj("tool" -> ujson.Obj("driver" -> driver), "results" -> ujson.Arr.from(results))
Files.writeString(Paths.get(report), ujson.write(ujson.Obj("version" -> "2.1.0", "runs" -> ujson.Arr(run))))
