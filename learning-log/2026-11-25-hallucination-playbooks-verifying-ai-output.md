# Day 23 — Hallucination in Playbooks: Verifying AI Output

📅 25 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Yesterday's copilot trial had one result worth sitting with: on sign-ins, 5
of the 6 overturned verdicts came from summaries with claims that had no
evidence link, statements like "no other sign-ins from this IP in the last 7
days". Today is about where those statements come from and how to check
them before someone closes an incident on one.

NIST's term is **confabulation**: generative AI systems that "generate and
confidently present erroneous or false content", colloquially called
hallucinations
([NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)).
The important word is *confidently*. A SOC copilot doesn't flag its own
guesses, and in a ticket a guess reads exactly like a finding.

It also isn't going away with the next model. Researchers at OpenAI argue
that models hallucinate partly because training and evaluation "reward
guessing over acknowledging uncertainty"
([Kalai et al., 2025](https://arxiv.org/abs/2509.04664), vendor research).
And grounding the model in your own documents helps without solving it: a
preregistered Stanford study found that legal research tools from LexisNexis
and Thomson Reuters, marketed with retrieval-augmented generation as
reducing or "eliminating" hallucinations, each hallucinated "more than 17%
of the time"
([Magesh et al., Journal of Empirical Legal Studies, 2025](https://law.stanford.edu/publications/hallucination-free-assessing-the-reliability-of-leading-ai-legal-research-tools/)).
So the practical question isn't "which model doesn't hallucinate?" It's
"what checks catch it before it costs us?"

---

## The concept

### What a hallucination looks like in a SOC

It rarely looks absurd. It looks like something an analyst would write.
Every example in the middle column is fictional; the facts in the right-hand
columns are checked against the linked documentation.

| Artefact | A plausible hallucination | What's actually true | Fails loudly or quietly? |
|---|---|---|---|
| **Column name** | `SigninLogs \| where SourceIP == "198.51.100.23"` | The column is `IPAddress` ([SigninLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)) | **Loudly.** KQL returns a semantic error such as `Failed to resolve scalar expression named 'x'` ([Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-errors)). Identifiers are case-sensitive too, so `signinlogs` fails as well ([entity names](https://learn.microsoft.com/en-us/kusto/query/schema-entities/entity-names)) |
| **Filter value** | `where ResultType == "Success"` | `ResultType` is a string error code, and `0` means success | **Quietly.** The query runs and returns zero rows, because no row ever has that value |
| **Table coverage** | "No logons to the file server from other hosts" from `DeviceLogonEvents` | The table only holds devices that send to it. A server that was never onboarded has no rows | **Quietly.** Zero rows, which is true of every host that isn't there |
| **Event ID meaning** | "Event 4722 shows the account was created" | 4720 is "A user account was created"; 4722 is "A user account was enabled" ([4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720), [4722](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4722)) | **Quietly.** The query is right; the story in the ticket is wrong |
| **Package or tool name** | "Install the `x` helper with pip" | It may not exist, and someone may register it | **Quietly, then dangerously** (next section) |
| **Playbook step** | A plausible response step composed from memory, not from your runbook | Your runbook may say something different for a reason the model can't know | Depends on whether the step errors or just does the wrong thing |

ANALYSIS.md describes the worst case as a wrong field name that returns zero
rows. Having checked the KQL documentation, I'd refine that: in KQL a column
that doesn't exist fails loudly, which is the good outcome. The quiet failures
are a **wrong value**, a **table that doesn't cover the thing you asked
about**, and a **wrong time window**. All three return zero rows from a
query that looks correct.

### Zero rows has three meanings

This is the single most useful idea for today. When a query returns nothing,
it means one of these, and only a second query tells you which:

| Zero rows because… | Control check | Example |
|---|---|---|
| **It's genuinely clean** | The table has data in the window, and the filter values occur in it normally | No MFA changes for this user, while `AuditLogs` shows hundreds of other events that day |
| **There's no data** | Count the table's rows in the same window with no filter. Zero means a broken connector or an empty table, not a clean result | `DnsEvents` has had no rows since a connector stopped |
| **The filter can never match** | Look for the literal value anywhere in the table over the last 30 days. If it's never appeared, the query is asking about something that doesn't exist | `ResultType == "Success"`, or a device name that's never been onboarded |

A copilot that writes "no evidence of X" has collapsed these three into one
sentence. The analyst's job, or better, the harness's job, is to separate
them again.

### When attackers use the hallucination

Package names are the case where a hallucination becomes an attack surface.
Spracklen and colleagues generated 576,000 code samples with 16 models and
found the average share of hallucinated packages was "at least 5.2% for
commercial models and 21.7% for open-source models", with 205,474 unique
invented package names
([USENIX Security 2025](https://arxiv.org/abs/2406.10279v3)). If a name is
invented often enough, someone can register it.

MITRE ATLAS lists both halves:
[AML.T0062 Discover LLM Hallucinations](https://atlas.mitre.org/techniques/AML.T0062)
(prompting models to find packages, commands, URLs or email addresses with
no real source) and
[AML.T0060 Publish Hallucinated Entities](https://atlas.mitre.org/techniques/AML.T0060)
(registering the package, site or address so the victim lands on something
the attacker controls). The ATLAS case study is a hallucinated
`huggingface-cli` package suggested for `pip install`, when the real tool is
part of `huggingface_hub`. For a SOC, the relevant version is a remediation
script or "helpful" tool a copilot suggests during an incident, when people
are in a hurry. It's the same supply chain risk as Day 17's MCP servers,
arriving through a chat window.

OWASP files all of this under
[LLM09:2025 Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/),
and names the human half of the problem too: **overreliance**, when users
"place excessive trust in LLM-generated content, failing to verify its
accuracy".

### A verification ladder

The checks below are in order of cost. As judgement, not a standard: the
first four should be automatic in whatever harness runs the copilot's
queries, and the last two are where people come in.

| Step | Check | Catches | Trade-off |
|---|---|---|---|
| **1. Compile** | Did the query run without error? | Invented columns and tables | Free, but a failed query must stop the claim, not just get logged |
| **2. Coverage** | Rows in the same table and window with no filter | Broken connectors, empty tables | One extra cheap query per claim |
| **3. Value check** | Does each literal in the `where` clause appear in the table in the last 30 days? | Wrong values, unonboarded hosts, misspelt accounts | Can be expensive on big tables. Limit it to absence claims |
| **4. Reference check** | Event IDs, ATT&CK IDs and package names compared with an authoritative list kept by you | Wrong meanings, invented IDs, unregistered or brand-new packages | The list has to be maintained, or it becomes its own source of errors |
| **5. Evidence link** | Every factual claim points to the query and the result row | Claims with nothing behind them (Day 22's "unsupported") | Longer summaries, and analysts may learn to write fewer claims |
| **6. Known positive** | Before trusting a new or generated detection, run it on a case where you know the answer is "yes" | Queries that compile, cover the right table, and still look in the wrong place | Needs test data, which needs an owner |

For playbooks, ANALYSIS.md's rule is **retrieve, don't invent**. In practice
that means the model chooses steps by ID from your approved runbook and fills
in parameters, and code rejects any step ID that isn't in the runbook. The
model can still pick the wrong step, but it can't make one up. The cost is
flexibility: a novel incident may need a step that isn't written yet, and
that should be a human decision, recorded so the runbook improves.

---

## Sample logs

Everything is fictional. After Day 22, Northwind changed its copilot
harness. Every factual claim in a copilot summary is now written to
**`NWCopilotEvidence_CL`, a fictional custom table** (not a Microsoft
schema), along with the result of the harness's control checks:

- `ClaimType`: Presence ("3 failed sign-ins"), Absence ("no successful
  sign-ins") or Reference (a statement about what an ID means)
- `RowsReturned` and `CompileStatus`: the copilot's own query
- `TableRowsInWindow`: the same table and window with no filter (step 2)
- `FilterValueSeen30d`: whether the query's literal values appear in the
  table in the last 30 days (step 3; blank when not checked)
- `RefCheck`: the result of the reference lookup (step 4)

All 14 rows. Times in UTC; Northwind is on AEDT (UTC+11).

```
TimeGenerated         Incident  Claim  ClaimType  QueryTable         RowsReturned  CompileStatus  TableRowsInWindow  FilterValueSeen30d  RefCheck  IncidentStatus
2026-11-23T22:14:05Z  5301      C1     Presence   SigninLogs         3             Ok             12950              true                          Closed-Benign
2026-11-23T22:14:05Z  5301      C2     Absence    SigninLogs         0             Ok             12950              false                         Closed-Benign
2026-11-23T22:14:05Z  5301      C3     Absence    AuditLogs          0             Ok             310                true                          Closed-Benign
2026-11-24T00:41:37Z  5302      C1     Absence    DeviceLogonEvents  0             Ok             48200              false                         Active
2026-11-24T00:41:37Z  5302      C2     Presence   DeviceEvents       1             Ok             61400              true                          Active
2026-11-24T02:03:19Z  5303      C1     Reference  SecurityEvent      1             Ok             95100              true                Mismatch  Active
2026-11-24T02:03:19Z  5303      C2     Absence    SecurityEvent      0             Ok             95100              true                          Active
2026-11-24T03:27:50Z  5304      C1     Absence    UrlClickEvents     0             Ok             2210               true                          Closed-Benign
2026-11-24T03:27:50Z  5304      C2     Absence    DnsEvents          0             Ok             0                                                Closed-Benign
2026-11-24T04:55:12Z  5305      C1     Absence    SigninLogs         0             Failed         13120                                            Closed-Benign
2026-11-24T04:55:12Z  5305      C2     Presence   SigninLogs         1             Ok             13120              true                          Closed-Benign
2026-11-24T06:12:44Z  5306      C1     Presence   EmailEvents        4             Ok             30400              true                          Closed-Benign
2026-11-24T06:12:44Z  5306      C2     Absence    EmailEvents        0             Ok             30400              true                          Closed-Benign
2026-11-24T13:20:08Z  5307      C1     Absence    DnsEvents          0             Ok             0                                                Active
```

The claim text for the rows that matter (also fictional):

```
5301 C2  "No successful sign-ins from 203.0.113.45 in the last 7 days."      query: ResultType == "Success"
5302 C1  "No logons to NW-FS02 from other hosts."                             query: DeviceName == "nw-fs02"
5303 C1  "Event 4722 shows svc-backup2 was created at 01:52."                 the event is real; 4722 means enabled
5304 C2  "No DNS lookups for nw-payroll.example from any host."               DnsEvents empty since 20 Nov
5305 C1  "No sign-ins from 198.51.100.23 to other accounts."                  query used SourceIP: semantic error
5306 C2  "No replies were sent to the sender."                                genuine clean result
```

---

## What to look for

1. **Count the claims in scope.** 14 rows. 13 are from Tuesday 24 November
   in Sydney time, across 6 incidents. Incident 5307, at 13:20 UTC, is 00:20
   on Wednesday 25 November in Sydney, so it belongs to tomorrow's check, the
   same time-zone edge as Day 22.
2. **Presence claims are rarely the problem.** The 4 presence claims all
   returned rows. A claim that something happened comes with the rows that
   show it, so it's easy to check. The risk sits with the 8 **absence**
   claims, and 4 of them are hollow.
3. **5301 C2: the filter can never match.** `ResultType` holds error codes,
   with `0` for success, so `"Success"` has never appeared in 30 days.
   `SigninLogs` had 12,950 rows that day. The incident was closed as benign
   on a sentence that was never tested.
4. **5302 C1: the host isn't there.** `DeviceLogonEvents` is busy (48,200
   rows), but `nw-fs02` has never appeared in it. That's a coverage gap, and
   it deserves its own ticket regardless of the incident.
5. **5304 C2: no data at all.** `DnsEvents` has zero rows in the window. The
   claim isn't "clean", it's "we can't see". Also closed as benign.
6. **5305 C1: the query failed and the claim was written anyway.** The
   copilot used `SourceIP`; the column is `IPAddress`. KQL refused, which is
   exactly what you want, but the summary still said "no sign-ins". A failed
   query must block the claim, not sit in a log.
7. **5303 C1: right data, wrong story.** The event exists; the copilot
   described 4722 (enabled) as 4720 (created). An account being re-enabled
   and an account being created are different investigations.
8. **What clean looks like.** 5301 C3, 5303 C2, 5304 C1 and 5306 C2 are
   absence claims where the table had data and the values occur normally.
   Those are real negative results. Incident 5306 has no problems at all.

---

## Detection logic

**In plain English.** This isn't a detection for an attacker. It's a daily
check for copilot claims that rest on nothing.

- Keep claims logged on the previous day in Sydney time.
- Flag a claim when:
  - **BROKEN_QUERY**: an absence claim whose query failed to compile.
  - **NO_DATA**: an absence claim with zero rows, from a table with zero rows
    in the window.
  - **VALUE_NEVER_SEEN**: an absence claim with zero rows, where the filter
    value hasn't appeared in the table in 30 days.
  - **REF_MISMATCH**: a reference claim that fails the lookup.
- Group by incident. If the incident is already closed as benign, it needs
  reopening; if it's still active, the claim needs fixing before it closes.

**KQL (Microsoft Sentinel / Log Analytics).** `NWCopilotEvidence_CL` and its
columns are fictional. `case()`, `iff()`, `make_set()`, `make_list()` and
`take_any()` are standard KQL.

```kql
// Copilot evidence check: absence and reference claims that rest on nothing
let dayStart = datetime(2026-11-23T13:00:00Z);   // Tue 24 Nov 00:00 AEDT
let dayEnd   = datetime(2026-11-24T13:00:00Z);   // Wed 25 Nov 00:00 AEDT
NWCopilotEvidence_CL
| where TimeGenerated >= dayStart and TimeGenerated < dayEnd
| extend Flag = case(
    ClaimType == "Absence" and CompileStatus == "Failed",                            "BROKEN_QUERY",
    ClaimType == "Absence" and RowsReturned == 0 and TableRowsInWindow == 0,          "NO_DATA",
    ClaimType == "Absence" and RowsReturned == 0 and FilterValueSeen30d == false,     "VALUE_NEVER_SEEN",
    ClaimType == "Reference" and RefCheck == "Mismatch",                              "REF_MISMATCH",
    "")
| where isnotempty(Flag)
| summarize Flags = make_set(Flag), FlaggedClaims = count(), Claims = make_list(Claim),
            Status = take_any(IncidentStatus)
    by Incident
| extend Action = iff(Status == "Closed-Benign", "REOPEN", "FIX BEFORE CLOSE")
| order by Action desc, Incident asc
| project Action, Incident, Status, Flags, FlaggedClaims, Claims
```

The order of the `case()` branches matters. A failed query is reported as
BROKEN_QUERY even if other columns would also match, because that's the
first thing to fix. A blank `FilterValueSeen30d` (not checked) doesn't match
`== false`, so the rule never flags a claim just because a check didn't run;
see the tuning note on that.

I ran the same logic in Python over the 14 sample rows:

```
raw rows 14
in window 13 incidents 6
Counter({'Absence': 8, 'Presence': 4, 'Reference': 1})
flagged claims 5
absence claims 8 flagged 4
('REOPEN', 5301, ['VALUE_NEVER_SEEN'], 1, ['C2'], 'Closed-Benign')
('REOPEN', 5304, ['NO_DATA'], 1, ['C2'], 'Closed-Benign')
('REOPEN', 5305, ['BROKEN_QUERY'], 1, ['C1'], 'Closed-Benign')
('FIX BEFORE CLOSE', 5302, ['VALUE_NEVER_SEEN'], 1, ['C1'], 'Active')
('FIX BEFORE CLOSE', 5303, ['REF_MISMATCH'], 1, ['C1'], 'Active')
output rows 5
5307 flag (outside window): NO_DATA
```

**5 rows**: three incidents to reopen (5301, 5304, 5305) and two to fix
before closing (5302, 5303). Incident 5306 is excluded because both its
claims are supported. Incident 5307 would be NO_DATA, but it falls on
Wednesday in Sydney and appears in tomorrow's run.

**What I verified and what I didn't.** The table and rows are fictional. The
real-world facts the sample relies on are from Microsoft Learn: `IPAddress`
and `ResultType` in `SigninLogs`, the semantic error for an unresolved name,
case-sensitive identifiers, and the meanings of 4720 and 4722. I haven't run
the query against a live workspace.

**Tuning note:**

- **The harness is the real control, not this query.** This check finds
  hollow claims after the fact. The better design blocks them: a failed
  query or a NO_DATA result should stop the copilot writing the sentence at
  all, and replace it with "couldn't check: no data in `DnsEvents`".
- **Treat "not checked" as its own state.** If the value check is skipped
  for cost, a blank `FilterValueSeen30d` passes this rule. A stricter version
  flags absence claims on closed incidents where the value check didn't run.
- **Coverage gaps outlive the incident.** 5302 and 5304 point at an
  unonboarded server and a stopped connector. Route NO_DATA and
  VALUE_NEVER_SEEN on host names to whoever owns log sources, or the same
  hollow claim comes back next week.
- **Watch the denominator.** Five flags in 13 claims is a lot, but the
  number that matters per week is hollow absence claims on closed incidents.
  Track it alongside Day 21's overturn rate and Day 22's unsupported-summary
  rate; if they move together, the copilot is the cause.
- **Keep the reference list current.** A stale event ID or package list
  produces false REF_MISMATCH flags, and analysts will stop reading them.

**ATLAS mapping:** [AML.T0062](https://atlas.mitre.org/techniques/AML.T0062)
and [AML.T0060](https://atlas.mitre.org/techniques/AML.T0060) for the package
case. The rest of today is a reliability problem rather than an attack.
Tomorrow (Day 24) is the attack version: someone writing text into your logs
so the copilot says what they want.

---

## Your turn

1. For 5302 C1, write the two control queries (coverage and value check) in
   plain English or KQL, then rewrite the copilot's sentence so it's true.
2. A copilot proposes this playbook step during a ransomware incident:
   "install the recommended decryptor package and run it on the file
   server". List every check you'd want before that step runs, and say which
   are automatic and which need a person.
3. Design the "retrieve, don't invent" interface for Northwind's runbook:
   what exactly does the model output, what does code check, and what
   happens when the right step doesn't exist?
4. Running value checks on every absence claim doubles query costs. Decide
   which claims always get checked and which are sampled, and explain the
   risk you're accepting.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- NIST: [AI 600-1, Generative Artificial Intelligence Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) (section 2.2 Confabulation; action MS-2.5-003, "review and verify sources and citations")
- OWASP: [LLM09:2025 Misinformation](https://genai.owasp.org/llmrisk/llm092025-misinformation/) (hallucination, overreliance, non-existent code libraries)
- Kalai, Nachum, Vempala and Zhang (OpenAI, vendor research): [Why Language Models Hallucinate](https://arxiv.org/abs/2509.04664)
- Magesh et al. (Stanford): [Hallucination-Free? Assessing the Reliability of Leading AI Legal Research Tools](https://law.stanford.edu/publications/hallucination-free-assessing-the-reliability-of-leading-ai-legal-research-tools/) (Journal of Empirical Legal Studies, 2025)
- Spracklen et al.: [We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs](https://arxiv.org/abs/2406.10279v3) (USENIX Security 2025)
- MITRE ATLAS: [AML.T0062 Discover LLM Hallucinations](https://atlas.mitre.org/techniques/AML.T0062) · [AML.T0060 Publish Hallucinated Entities](https://atlas.mitre.org/techniques/AML.T0060)
- Microsoft Learn: [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) · [Entity names (case sensitivity)](https://learn.microsoft.com/en-us/kusto/query/schema-entities/entity-names) · [Handle errors in advanced hunting](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-errors) · [Event 4720](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720) · [Event 4722](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4722)
- This log: [ANALYSIS.md, Hallucination risk in playbooks](../ANALYSIS.md#hallucination-risk-in-playbooks) · [Day 17](2026-11-19-agent-tools-mcp-permissions-tool-poisoning.md) (agent tools and supply chain) · [Day 19](2026-11-21-logging-llm-apps-detect-abuse.md) (logging LLM apps) · [Day 22](2026-11-24-ir-copilots-measuring-real-value.md) (overturns and unsupported summaries)

⬅️ [Learning log index](README.md) · ➡️ Day 24: Prompt injection through logs: attacking the SOC's AI (26 Nov)
