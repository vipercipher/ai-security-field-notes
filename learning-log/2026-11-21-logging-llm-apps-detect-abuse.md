# Day 19 — Logging LLM Apps So You Can Detect Abuse

📅 21 November 2026 · 🏷️LLM security · ⏱️ ~30 min

---

## Why it matters

Every entry since Day 10 has started with a made-up Northwind table:
`NorthwindLLMAudit_CL`, the agent gateway, the guardrail log, the persistent
writes from Day 18. Each one made the detection possible, and I invented
each one. Today asks where those rows would actually come from, which ones a
cloud provider gives you for free, which you have to build, and what it
costs to keep them.

There's a second reason. Attackers check whether you're logging. In the
first published LLMjacking case, people using stolen cloud keys asked the
model service whether prompt logging was switched on before they used it
([Sysdig, vendor research](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack)).
That makes "is logging on, and did it just change?" a detection in its own
right.

---

## The concept

### Three layers, and none of them sees everything

Assume (fictionally) that Ask Northwind calls a hosted model through Amazon
Bedrock. AWS is the example because its logging is well documented. Azure
and Google have similar layers with different names. There are three places
a record can come from:

| | **Cloud audit log** (CloudTrail) | **Model invocation log** (Bedrock) | **Your gateway / app log** |
|---|---|---|---|
| **On by default?** | Yes, for management events | **No.** "Model invocation logging is disabled by default" ([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)) | Only if you build it |
| **Who it names** | The AWS identity that made the call | The AWS identity (`identity.arn`), plus any tags the caller sends | The **end user**, session and agent |
| **Prompt and answer** | No. Sysdig: prompts and results "are not stored in Cloudtrail" | Yes, request and response bodies up to 100 KB inline, larger ones to S3 | Your choice (see below) |
| **Token counts** | No | `input.inputTokenCount`, `output.outputTokenCount` | If you record them |
| **Retrieved items, tool calls, guardrail verdicts, approvals** | No | Only what's inside the request body, unlabelled | Yes, and only here |
| **Blind spots** | No content | Only calls through the `bedrock-runtime` endpoint. AWS says calls through `bedrock-mantle` are "not currently captured" | Anything that doesn't go through the gateway |

What the AWS docs confirm about the first column: `InvokeModel`,
`InvokeModelWithResponseStream`, `Converse` and `ConverseStream` are logged
in CloudTrail as **management events**, with `eventSource`
`bedrock.amazonaws.com`
([AWS](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)).
Knowledge base retrieval, agent calls and `ApplyGuardrail` are **data
events**, which you have to switch on separately.

The point of the table: the provider's logs tell you *which key* called the
model and, if you turn them on, *what it said*. Only your own gateway knows
*which person* asked, what was retrieved, which tools ran and who approved
them. Every detection this month that mattered (Day 13's taint rule, Day
16's tool arguments, Day 18's reads after a poisoned write) needed that
third column.

### The record I'd want for every model call

My working list for Northwind's gateway, judgement rather than a standard.
Each row traces back to a day that needed it:

| Field | Why | Needed on |
|---|---|---|
| `RequestId`, also sent to the model provider | Joins your row to the provider's invocation log | Today |
| `SessionId`, `UserUpn`, `Agent` | The provider only sees the app's role, so "who" lives here | Every day |
| Model ID and version | A model change can change behaviour and guardrail scores | Day 15 |
| Input and output tokens | Cost abuse and runaway loops | Day 10 (S-205), today |
| Retrieved item IDs with trust tier | Blast radius when a source turns out to be poisoned | Days 12 and 18 |
| Tool name, **full arguments**, decision, reason | Arguments are where data leaves | Days 13, 16 and 17 |
| Guardrail check, score, verdict | Probing shows up as scores creeping down | Day 15 |
| Approval: who, what the screen showed, seconds before clicking | `Approval = human` alone says nothing about whether anyone read it | Days 13 and 16 |
| Finish reason, error | Failed calls are early warning | NCSC (below) |
| Content: hash always, text per policy | See the next section | Today |

[OpenTelemetry's GenAI semantic conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md)
are the closest thing to a common schema. They're still marked
**Development**, so names may change. `gen_ai.operation.name` and
`gen_ai.provider.name` are Required and `gen_ai.response.finish_reasons` is
Recommended. The content attributes, such as `gen_ai.output.messages` and
`gen_ai.system_instructions`, are **Opt-In**. Using them makes it easier to
move between observability tools later. They don't cover end-user identity,
trust tiers or approvals, so you'd add those yourself.

### Logging the content: the real trade-off

The NCSC's advice is to log "enough information to identify suspicious
activity, potentially including full input and output of the LLM, as well
as tool use, API calls etc." It adds the line ANALYSIS.md leans on: "detecting
and responding to failed tool calls or API calls could identify earlier
stages of an attack"
([NCSC, December 2025](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)).

OpenTelemetry takes the opposite default for a reason: prompts and outputs
"are considered sensitive and are often large in size", so instrumentations
"SHOULD NOT capture them by default, but SHOULD provide an option for users
to opt in". In Australia, the OAIC is explicit that privacy obligations
"apply to any personal information input into an AI system, as well as the
output data generated by AI (where it contains personal information)"
([OAIC, October 2024](https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/guidance-on-privacy-and-the-use-of-commercially-available-ai-products)).
A prompt log is a copy of every customer email, ticket and pasted
spreadsheet that went through the assistant.

| Option | What you can investigate | What it costs |
|---|---|---|
| **Metadata only** (IDs, tokens, tools, verdicts, hashes) | Who, when, how much, which tools, which sources | You can't tell *what* an injection said, or confirm a leak's contents |
| **Redacted content** | Most investigations | Redaction misses things, and the redactor is one more component to trust |
| **Full content, separate store** | Everything, including exact replay | A second sensitive dataset: access control, retention, breach scope, privacy notice |
| **Nothing** | Almost nothing | Every detection in this log stops working |

What I'd choose for Northwind, and it's judgement: metadata and hashes for
every call, kept with the other security logs. Full content goes to a
separate store with a short retention period agreed with the privacy team,
readable by a small group, and every read of it is logged. ANALYSIS.md says
to settle this with legal before launch, and I agree. Arguing about
retention during an incident is the worst time to do it.

Two warnings about the content store. Day 18 showed that text in a store can
be written by an attacker, and a prompt log is full of attacker-written
text. When a SOC copilot summarises those logs (Day 24), that's an injection
path. And the store becomes a target in its own right, worth more than the
assistant, because it holds everything the assistant was ever shown.

### Attackers check whether you're logging

Sysdig's May 2024 write-up (vendor research) is still the clearest case:

- Cloud keys were stolen from a vulnerable Laravel server. The attackers
  tested them against ten AI services.
- On Bedrock, they called `InvokeModel` with an invalid parameter. A
  `ValidationException` meant "this key works and the model is enabled". An
  `AccessDenied` meant it didn't. No real prompt was needed.
- They called `GetModelInvocationLoggingConfiguration` to see whether
  prompts were being logged. The reverse-proxy software involved says it
  won't use a key that has logging enabled.
- Sysdig's worst-case estimate was **over US$46,000 a day** in model costs
  for the victim, calculated from 2024 Claude 2 pricing and quotas across
  four regions. That's their arithmetic, not a measured loss.

The frameworks now name this. MITRE ATT&CK's
[T1496.004 Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004/)
mentions "LLMJacking by leveraging reverse proxies". Switching off a log is
[T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/)
(the old T1562.008 now redirects there). Driving up someone else's model
bill is ATLAS [AML.T0034 Cost Harvesting](https://atlas.mitre.org/techniques/AML.T0034)
and OWASP [LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/),
whose mitigations include rate limits and per-user quotas and to "continuously
monitor resource usage and implement logging to detect and respond to
unusual patterns of resource consumption".

### Make the gateway's calls recognisable

Bedrock lets the caller attach `requestMetadata`, key-value tags that land
in the invocation log. AWS notes it's the only field the caller supplies.
Every other field is filled in by Bedrock. Northwind's gateway sends a
pseudonymous session ID and its own request ID there. A UPN would put
personal information into one more log, so it doesn't.

That gives a simple test. A model call **with** the gateway's tags came
through the gateway. A call **without** them came from somewhere else, such
as a developer's script, a forgotten integration or a stolen key. Because
the caller sets the tags, an attacker who knows the format can copy them.
Treat their absence as strong evidence and their presence as weak evidence.

---

## Sample logs

All times are UTC (21:14 UTC on 20 November is 08:14 on 21 November in
Sydney). Everything is fictional. The account ID is the example ID AWS uses
in its documentation.

**CloudTrail** (real field names, fictional events). An extract of 12
Bedrock events from 4 identities. `eventSource` is `bedrock.amazonaws.com`
on every row and is left out to save space. The ARN prefix
`arn:aws:sts::123456789012:assumed-role/` is shortened to `role/`, and
`arn:aws:iam::123456789012:user/` to `user/`:

```
eventTime             eventName                                  userIdentity.arn                          sourceIPAddress  errorCode            requestParameters.modelId
2026-11-20T20:58:12Z  Converse                                   role/ask-northwind-app/gw-01              192.0.2.10       -                    anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T20:58:40Z  Converse                                   role/ask-northwind-app/gw-01              192.0.2.10       -                    anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T21:14:03Z  GetModelInvocationLoggingConfiguration     user/svc-reporting-ci                     203.0.113.66     -                    -
2026-11-20T21:14:09Z  InvokeModel                                user/svc-reporting-ci                     203.0.113.66     ValidationException  anthropic.claude-v2
2026-11-20T21:14:10Z  InvokeModel                                user/svc-reporting-ci                     203.0.113.66     ValidationException  anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T21:14:12Z  InvokeModel                                user/svc-reporting-ci                     203.0.113.66     AccessDenied         amazon.titan-text-express-v1
2026-11-20T21:20:30Z  DeleteModelInvocationLoggingConfiguration  user/svc-reporting-ci                     203.0.113.66     -                    -
2026-11-20T21:22:00Z  InvokeModel                                user/svc-reporting-ci                     198.51.100.140   -                    anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T21:22:01Z  InvokeModel                                user/svc-reporting-ci                     198.51.100.140   -                    anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T21:35:00Z  PutModelInvocationLoggingConfiguration     role/northwind-iac-deploy/drift-check     192.0.2.20       -                    -
2026-11-20T21:40:15Z  Converse                                   role/ask-northwind-app/gw-01              192.0.2.10       -                    anthropic.claude-sonnet-4-20250514-v1:0
2026-11-20T21:47:30Z  GetModelInvocationLoggingConfiguration     role/secops-config-audit/scanner          192.0.2.30       -                    -
```

**Reconciliation**, 21:00 to 22:00 (fictional counts). Successful model
calls counted three ways for the whole hour, not just the extract above.
"With gateway tags" means the invocation log record carried the gateway's
`requestMetadata`:

```
Window (UTC)   CloudTrail calls  Invocation log  ...with gateway tags  Gateway rows
21:00-21:15                  38              38                    38            38
21:15-21:30                 247              24                    24            33
21:30-21:45                 712             455                    35            40
21:45-22:00                  39              39                    39            39
Total                      1036             556                   136           150
```

Context (fictional): `svc-reporting-ci` is an IAM user with a long-lived
access key, used by a nightly reporting job. It was given `bedrock:*` "for a
week" in October so the job could try summarising reports, and nobody took
it back. It has never called Bedrock from anywhere but the build server,
`192.0.2.40`. `northwind-iac-deploy/drift-check` is the platform team's
infrastructure-as-code job, which resets drifted settings every 15 minutes.
`secops-config-audit/scanner` is the security team's posture scanner, which
reads configuration every 30 minutes. In the full CloudTrail data,
`svc-reporting-ci`'s last model call is at 21:41:50.

---

## What to look for

1. **Count first.** CloudTrail extract: **12** events from **4**
   identities, **8** model calls (5 `InvokeModel`, 3 `Converse`) and **4**
   logging-configuration calls (2 Get, 1 Delete, 1 Put).
   `svc-reporting-ci` accounts for **7** of the 12.
2. **The probe is Sysdig's pattern.** At 21:14, a key that has never touched
   Bedrock from outside the build server checks the logging configuration,
   then makes **3** model calls in 3 seconds against 3 different models,
   all of which fail. Two `ValidationException`s say "this works", and one
   `AccessDenied` says "not this model". No prompt was needed.
3. **Then it turns logging off.** The Delete at 21:20:30 comes from the
   same key and the same IP. Ninety seconds later the successful calls
   start, from a **different** IP, `198.51.100.140`. That fits a proxy
   using the key, but it's an inference from two rows.
4. **The reconciliation shows the size of it.** CloudTrail counted **1,036**
   successful model calls in the hour. The gateway made **150**. That leaves
   **886** calls (214 + 672) that never went through Ask Northwind.
5. **Turning logging off blinded Northwind too.** Between 21:20 and 21:35
   the invocation log is missing **14** of the gateway's own calls (9 + 5).
   The gateway log still has them, which is the case for keeping your own
   copy and not relying on the provider's.
6. **The drift job fixed it, by accident.** The Put at 21:35 is the
   infrastructure-as-code job restoring logging. After that, the invocation
   log has **420** records with no gateway tags (455 − 35). Those are the
   attacker's prompts, now on record. `svc-reporting-ci`'s last call is
   at 21:41:50, about seven minutes later. That fits the proxy software's
   stated rule of avoiding keys that have logging enabled, but nothing here
   proves it.
7. **The noise.** The 3 `ask-northwind-app` calls are normal traffic. The
   21:47 Get is the posture scanner, and it would make the Get on its own a
   noisy signal.

---

## Detection logic

**In plain English:**

- Alert on any change to Bedrock's model invocation logging (Put or Delete)
  by anyone except the infrastructure-as-code role. Logging should change
  through a reviewed deployment and nothing else.
- Alert on model calls that fail with `ValidationException` or an
  access-denied error. That's what a key being tested looks like. Northwind's
  gateway validates requests before sending them, so these should be rare
  from the app.
- Don't alert on `GetModelInvocationLoggingConfiguration` alone, because
  scanners read it all day. Use it as context when triaging the other two.
- Separately, compare call counts across the three layers every hour (the
  reconciliation). The Sigma rule can't do that, and it's what catches
  successful abuse.

**Sigma rule (AWS CloudTrail):**

```yaml
title: Bedrock Invocation Logging Changed or Model Access Probed
id: 0b7f3c2e-5d1a-4e8b-9c6f-2a4d8e1b7c90
status: experimental
description: |
    Detects changes to Amazon Bedrock model invocation logging, and model calls that
    fail in the way stolen keys fail when an attacker tests them (LLMjacking).
references:
    - https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html
    - https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack
author: Northwind SOC (fictional)
date: 2026-11-21
tags:
    - attack.defense-impairment
    - attack.t1685.002
    - attack.impact
    - attack.t1496.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_logging_change:
        eventSource: 'bedrock.amazonaws.com'
        eventName:
            - 'DeleteModelInvocationLoggingConfiguration'
            - 'PutModelInvocationLoggingConfiguration'
    selection_probe:
        eventSource: 'bedrock.amazonaws.com'
        eventName:
            - 'InvokeModel'
            - 'InvokeModelWithResponseStream'
            - 'Converse'
            - 'ConverseStream'
        errorCode:
            - 'ValidationException'
            - 'AccessDenied'
            - 'AccessDeniedException'
    filter_main_iac:
        userIdentity.arn|contains: ':assumed-role/northwind-iac-deploy/'
    condition: 1 of selection_* and not filter_main_iac
falsepositives:
    - Platform engineers changing logging by hand during an outage
    - Developers sending malformed requests while testing a new model
level: high
```

On the sample, the rule fires on **4 events**, all from `svc-reporting-ci`:
the 3 failed calls at 21:14 and the Delete at 21:20. I ran the same logic in
Python over the 12 rows and the reconciliation counts (rows that didn't
alert, and the two quiet windows, trimmed from the output):

```
rows 12 identities 4 Counter({'InvokeModel': 5, 'Converse': 3, 'GetModelInvocationLoggingConfiguration': 2, 'DeleteModelInvocationLoggingConfiguration': 1, 'PutModelInvocationLoggingConfiguration': 1})
2026-11-20T21:14:09Z InvokeModel                  svc-reporting-ci ValidationException -> ALERT
2026-11-20T21:14:10Z InvokeModel                  svc-reporting-ci ValidationException -> ALERT
2026-11-20T21:14:12Z InvokeModel                  svc-reporting-ci AccessDenied -> ALERT
2026-11-20T21:20:30Z DeleteModelInvocationLogging svc-reporting-ci - -> ALERT
alerts 4 Counter({'svc-reporting-ci': 4})
totals ct,inv,invmeta,gw [1036, 556, 136, 150]
21:15-21:30 not via gateway 214 gw calls missing from invocation log 9 invocation records without metadata 0
21:30-21:45 not via gateway 672 gw calls missing from invocation log 5 invocation records without metadata 420
unexplained total 886 missing total 14 no-meta total 420
```

What it excludes: the 21:35 Put (infrastructure-as-code filter), both Gets
(not in the rule), the 3 normal `Converse` calls, and the 2 successful
attacker calls at 21:22. **That last one is the gap.** The rule catches the
probe and the tampering, not the abuse itself. If the attacker had skipped
the test calls and found logging already off, this rule would have stayed
silent. Only the reconciliation would show 886 calls nobody can account
for.

**What I verified and what I didn't.** The event names, `eventSource`,
`errorCode` and `requestParameters.modelId` come from AWS's documentation
and Sysdig's published CloudTrail example. The three logging APIs are listed
by AWS. That model calls are management events is from AWS's CloudTrail page,
so they appear in a default trail. I did **not** confirm whether CloudTrail
records an IAM denial on these calls as `AccessDenied` or
`AccessDeniedException`, so the rule lists both. The logsource, the
`|contains` modifier, the `1 of selection_*` condition and the `filter_main_`
naming follow SigmaHQ's conventions and its existing Bedrock rules. The tags
use ATT&CK's current IDs. I haven't run the rule through a Sigma converter
or against a live trail, only as the Python equivalent. The reconciliation
counts and the gateway tag scheme are invented.

**Tuning note:** the infrastructure-as-code filter is only safe if that role
is locked down. Anyone who can assume it can change logging silently, so
alert on who assumes it too. Expect the probe half to fire when developers
try a new model with the wrong request format. Route those to the platform
team instead of the SOC, unless the identity has never called Bedrock
before or the IP is new. That's the context that made 21:14 obvious. Both
halves depend on someone having enabled invocation logging in the first
place. Check every region where Bedrock is enabled, not just the one you
use, because attackers in Sysdig's case called every region that supported
it. And notice what fixed this incident: a drift job, not the SOC. A
15-minute reset limited the blind spot. A daily one would have left the
attacker unlogged for most of a day.

---

## Your turn

1. Write the reconciliation as a scheduled query in KQL or SPL. You'll need
   the CloudTrail call count, the invocation log count with and without
   gateway tags, and the gateway count per 15 minutes. What threshold would
   you alert on, given that the counts never quite match in real life
   (retries, clock skew, ingestion delay)?
2. Northwind's privacy officer asks why full prompts need to be kept at
   all. Using today's sample, name one finding you could make with metadata
   only and one that needs the content. Then propose a retention period and
   who can read the content store, and say what an attacker gains if that
   store leaks.
3. `svc-reporting-ci` had `bedrock:*` for a job that never needed to
   change logging settings. Write the narrowest policy that job actually
   needs, and list the API calls in today's sample that it would have
   blocked.
4. Go back to Day 13's `Approval = human` problem. Design the fields an
   approval record needs so that a reviewer could later tell a careful
   approval from a reflex click. What will rubber-stamping look like in
   those fields?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- AWS: [Monitor model invocation using CloudWatch Logs and Amazon S3](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html) (default state, log format, `requestMetadata`) · [Monitor Amazon Bedrock API calls using CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html) (management vs data events)
- Sysdig Threat Research (vendor research): [LLMjacking: Stolen Cloud Credentials Used in New AI Attack](https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack) (May 2024)
- OpenTelemetry: [Semantic conventions for generative client AI spans](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md) (Development status; content capture is opt-in)
- NCSC: [Prompt injection is not SQL injection (it may be worse)](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection) (see "Monitor")
- OAIC: [Guidance on privacy and the use of commercially available AI products](https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/guidance-on-privacy-and-the-use-of-commercially-available-ai-products)
- OWASP Gen AI Security Project: [LLM10:2025 Unbounded Consumption](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)
- MITRE ATT&CK: [T1496.004 Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004/) · [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/) · MITRE ATLAS: [AML.T0034 Cost Harvesting](https://atlas.mitre.org/techniques/AML.T0034)
- SigmaHQ: [AWS Bedrock Guardrail Deleted](https://github.com/SigmaHQ/sigma/blob/master/rules/cloud/aws/cloudtrail/aws_cloudtrail_bedrock_guardrail_deleted.yml) (an existing community rule in the same style)
- This log: [ANALYSIS.md, layer 6: monitoring](../ANALYSIS.md#a-pragmatic-architecture) · [Day 10](2026-11-12-owasp-llm-top-10.md) (the first audit table, S-205's token count) · [Day 13](2026-11-15-threat-modelling-agents-trifecta-rule-of-two.md) (the gateway, `Approval = human`) · [Day 15](2026-11-17-runtime-guardrails-adaptive-attacks.md) (scores creeping down) · [Day 18](2026-11-20-data-poisoning-training-rag-memory.md) (reads after a poisoned write)

⬅️ [Learning log index](README.md) · ➡️ [Day 20: ML threat hunting: anomalies, UEBA and baselines (22 Nov)](2026-11-22-ml-threat-hunting-ueba-baselines.md)
