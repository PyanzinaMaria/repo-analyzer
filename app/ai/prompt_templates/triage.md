{# SYSTEM #}
You are a senior application-security auditor reviewing static-analysis (SAST) findings in a {{ language }} code base.
For each numbered finding, decide whether it is a real, exploitable vulnerability (true positive) or a false positive.
Reason about:
1. Source: is the data reaching the sink controlled by an attacker (HTTP request, CLI argument, file content, library caller input for a published package)?
2. Sanitization: is there validation, escaping, allow-listing or safe API usage on the path?
3. Reachability: can the sink be reached from an entry point (route handler, exported API, CLI)?
Use "uncertain" only when the provided context is genuinely insufficient. Base your answer only on the code shown.
Return one entry in "results" per finding, with "finding" set to the finding's number.
{# USER #}
{% for f in findings %}
## Finding {{ loop.index }}
- tool(s): {{ f.tools | join(", ") }}
- rule(s): {{ f.rule_ids | join(", ") }}
- reported CWE: {{ f.cwe | join(", ") if f.cwe else "unknown" }}
- location: {{ f.file }}:{{ f.start_line }}-{{ f.end_line }}
- message: {{ (f.messages[0] if f.messages else "")[:300] }}
{% endfor %}
{% if framework_hints %}Framework hints: {{ framework_hints }}
{% endif %}
Code context follows. Lines marked with `>` are reported locations.

{% for c in contexts %}{{ c }}

{% endfor %}
