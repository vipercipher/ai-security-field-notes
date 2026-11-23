# Day 22 — Incident Response Copilots: Measuring Real Value

📅 24 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Day 21 measured an ML detector. Today the thing being measured is a copilot:
an assistant that sits beside the analyst, summarises the incident, writes
the first query and drafts the ticket. These are now easy to get. Microsoft,
for example, says Microsoft 365 E5 and E7 customers get 400 Security Compute
Units a month for every 1,000 paid user licences, up to 10,000 a month, at no
extra cost, with the rollout that started on 18 November 2025 continuing to
all eligible customers
([Microsoft Learn](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion)).
When a tool arrives "free", nobody asks whether it's worth it, so a team can
switch it on and never find out what it changed.

And "what it changed" is harder to answer than it sounds. ANALYSIS.md says
SOC AI "earns its keep on narrow, repetitive work with a checkable answer".
The only way to know whether your work is like that is to measure it. Your
team's impression won't tell you, for reasons the evidence below makes
uncomfortably clear.

---

## The concept

### What the published evidence says

There isn't much of it, and most of it comes from the vendor. These are
**vendor research**: Microsoft authors studying Microsoft products. They're
still worth reading closely, because the authors are unusually open about
their limits.

| Study | Design | Finding | Read it with |
|---|---|---|---|
| [Bono, Grana and Xu: SOC productivity in live operations](https://arxiv.org/html/2411.03116v2) | Observational. Defender XDR metadata from 150+ organisations, March–August 2024. Propensity score matching, then difference-in-differences | A 30.13% reduction in mean time to resolution three months after Security Copilot adoption, against a control group | Months 1 and 2 weren't significant (p = 0.82 and 0.40). Only incidents **resolved within 12 hours** were counted. The authors say unobserved confounders "inhibit causal identification", and that organisations willing to pay are "likely the ones that would most benefit", so the estimate may overstate the effect for everyone else |
| [Bono and Xu: RCT for IT administrators](https://arxiv.org/html/2411.01067v2) | Randomised. 181 freelancers recruited through Upwork, three admin scenarios, graded against answer keys | 34.53% better accuracy, 29.79% less time | A lab. The authors say "no laboratory can exactly replicate the nuances of live operations" |
| [Bono: RCT for a phishing triage agent](https://arxiv.org/html/2511.13860v1) | Randomised. 167 external analysts, a 25-email queue, three arms | Up to 6.5 times the true positives per analyst minute; 77% better F1 score | **79–84% of the gain came from queue prioritisation** (resolving likely-benign emails first). The agent's verdicts and explanations accounted for 13–17% |

Two things stand out. The best result is on the narrowest task, reported
phishing, which is exactly ANALYSIS.md's point. And in that study, most of
the value came from **reordering the queue**, not from the AI's explanation.
The chat-style part people picture when they hear "copilot" was the smaller
share.

One more study, from outside security, is the reason you can't skip
measuring. METR ran a randomised trial with 16 experienced open-source
developers on 246 tasks in their own repositories. Allowing AI tools made
the tasks take **19% longer**. Before starting, the developers forecast a 24%
speed-up. Afterwards, they still estimated AI had cut their time by 20%
([Becker et al., 2025](https://arxiv.org/abs/2507.09089)). It was early-2025
tools on a specific kind of work, and the authors don't claim it applies
elsewhere. The lesson that transfers is narrower: **people's sense of whether
an AI tool sped them up can point the wrong way.** A team survey is not a
measurement.

### Why mean time to resolve is a bad scoreboard

MTTR is the number every copilot pitch leads with. On its own it misleads in
three ways.

| Problem | What happens | What to measure alongside it |
|---|---|---|
| **Fast and wrong looks like a win** | A copilot that helps analysts close a suspicious sign-in as benign in 9 minutes "improves" MTTR, even if it should have been escalated | Verdict accuracy against an independent review |
| **The filter decides the answer** | Count only incidents resolved within 12 hours and you can't see incidents the copilot made *slower*, or ones that bounced back | Reopen rate; the full distribution, not a capped mean |
| **Before-and-after isn't cause and effect** | The month you switched the copilot on, you also changed a rule, hired someone, or had a quiet month | A concurrent control group, ideally randomised |

ANALYSIS.md makes the same point about autonomous actions: MTTR on its own
"rewards exactly the recklessness you're trying to avoid". The same applies
to a copilot.

### A scorecard that can actually say no

As judgement rather than a standard, this is the scorecard I'd use. Each
measure exists because a copilot can look good without it.

| Measure | How | Why it's there |
|---|---|---|
| **Triage time** | Median minutes from assignment to verdict, per alert type, per arm | The benefit. Median, because one stuck incident skews a mean |
| **Overturn rate** | Share of verdicts a blind QA reviewer reverses | Speed bought with accuracy shows up here |
| **Missed escalations** | Overturns where the analyst said benign and QA said malicious | The dangerous direction. ANALYSIS.md: an auto-closed true positive "leaves no trace unless you go looking" |
| **Evidence coverage** | Factual claims in the summary that link to a query and result | ANALYSIS.md: "Evidence or it didn't happen." An unlinked claim is where a hallucination hides (Day 23) |
| **Cost** | Compute units or licence cost per incident | "Free" capacity still runs out, and the allowance doesn't roll over month to month |

What's missing on purpose: number of prompts, "time saved" estimates from
analysts, and satisfaction scores. They're worth collecting, but none of them
can tell you the copilot made the SOC worse.

### Running a fair trial

The phishing study shows the shape of a good test: random assignment, the
same work for both groups, and answers checked against a known truth. A SOC
can approximate it.

| Choice | Do | Avoid |
|---|---|---|
| **Who gets the copilot** | Randomise **per incident** at creation, recorded in the ticket | Letting analysts choose. Keen users differ from sceptics, which is the selection problem the live-operations paper describes |
| **Which work** | Run it per alert type, and only where you have volume | Pooling everything. A gain on phishing can hide a loss on sign-ins |
| **Ground truth** | A QA reviewer who re-checks the verdict from raw evidence and doesn't know the arm | Using the analyst's own closing classification. That measures agreement with yourself |
| **Decide in advance** | Write down metrics and thresholds before the trial starts | Picking the metric that looked best afterwards |
| **Size** | Set a minimum per arm and don't judge below it | Calling a winner on a dozen incidents |

The trade-offs are real. Blind QA of every trial incident is expensive, and
a reviewer can often tell from the writing style which arm a ticket came
from. The control arm also means some incidents are worked without a tool the
team thinks helps. A trial that runs for three weeks on two or three alert
types is a reasonable compromise; a permanent one isn't.

### Where the data comes from

You may not need much new logging. If you use Security Copilot, its
activity can go to the Microsoft Purview unified audit log once a Security
Administrator turns on **Logging audit data in Microsoft Purview** in the
owner settings. The audit log holds admin events and activity metadata; prompt
and response content is "currently only included through Microsoft Purview
DSPM for AI", and default audit retention is 180 days
([Microsoft Learn](https://learn.microsoft.com/en-us/copilot/security/audit-log)).
That tells you *who used it and when*. It doesn't tell you whether the
verdict was right, so the QA result has to be recorded somewhere you can
query. It's the same habit as Day 19's logging of LLM apps: decide what
you'll need to judge the system, then make sure it's recorded.

---

## Sample logs

Everything is fictional. Northwind ran a three-week copilot trial from
**Monday 2 November to Sunday 22 November** (Sydney time, AEDT, UTC+11).
Each new incident in three alert types was randomly assigned to the
**Copilot** or **Control** arm when it was created. A senior analyst then
re-checked every verdict from raw evidence without seeing the arm, and
counted the factual claims in each summary and how many linked to a query
and result.

The results go into **`NWCopilotTrial_CL`, a fictional custom table**
(custom log tables in Log Analytics end in `_CL`). It's not a Microsoft
schema. Ten of its 168 rows, times in UTC:

```
TimeGenerated         IncidentNumber  AlertType           Arm      TriageMinutes  AnalystVerdict  QAVerdict  ClaimsInSummary  EvidenceLinks
2026-11-20T13:48:52Z  5103            Reported phishing   Copilot  2              Benign          Benign     5                5
2026-11-15T05:12:10Z  5141            Reported phishing   Control  19             Benign          Benign     5                5
2026-11-07T06:39:20Z  5203            Suspicious sign-in  Copilot  7              Malicious       Malicious  5                5
2026-11-16T22:52:24Z  5190            Suspicious sign-in  Copilot  18             Malicious       Benign     4                4
2026-11-19T12:57:29Z  5196            Suspicious sign-in  Copilot  12             Benign          Malicious  3                0
2026-11-11T18:11:05Z  5209            Suspicious sign-in  Copilot  7              Benign          Malicious  3                1
2026-11-12T20:59:47Z  5211            Suspicious sign-in  Control  12             Benign          Benign     3                3
2026-11-18T21:49:14Z  5241            Endpoint malware    Copilot  17             Malicious       Malicious  4                4
2026-11-21T02:00:00Z  5265            Reported phishing   Copilot  5              Benign          -          4                4
2026-11-22T13:05:00Z  5268            Suspicious sign-in  Copilot  8              Benign          Malicious  5                2
```

Results per alert type and arm, from the 164 rows that are inside the trial
window and have a QA verdict:

```
AlertType           Arm      n   MedianMin  Overturned       Missed  Unsupported
Reported phishing   Copilot  40  6          2  (5.0%)        1       3  (7.5%)
Reported phishing   Control  40  14         4  (10.0%)       2       2  (5.0%)
Suspicious sign-in  Copilot  30  9          6  (20.0%)       4       11 (36.7%)
Suspicious sign-in  Control  30  17         2  (6.7%)        1       3  (10.0%)
Endpoint malware    Copilot  12  20         1  (8.3%)        0       4  (33.3%)
Endpoint malware    Control  12  21         1  (8.3%)        0       1  (8.3%)
```

"Missed" means the analyst said benign and QA said malicious. "Unsupported"
means the summary had fewer evidence links than factual claims.

Context (fictional, not in the table): in the sign-in incidents QA
overturned, the copilot's summaries said things like "no other sign-ins from
this IP in the last 7 days" without a linked query.

---

## What to look for

1. **Count what's in scope.** 168 rows: 164 in the trial and reviewed, 3
   still waiting for QA (5265–5267), and 1 outside the window. Incident 5268
   was created at 13:05 UTC on Sunday 22 November, which is 00:05 on Monday
   23 November in Sydney, after the trial ended. Filter in UTC without
   converting and it slips in.
2. **Phishing: a real gain.** Median 6 minutes against 14, 57% lower, with
   no sign of lost accuracy (2 overturns against 4) and few unsupported
   summaries (3 of 40). It matches the published evidence: narrow task,
   checkable answer.
3. **Sign-ins: faster, and worse.** Median 9 minutes against 17, 47% lower.
   But QA reversed 6 of 30 copilot-arm verdicts (20.0%) against 2 of 30 in
   control (6.7%), and **4 of the 6 were missed escalations**: closed as
   benign, judged malicious on review. MTTR alone would report this alert
   type as the copilot's second-best result.
4. **The overturns cluster where evidence is missing.** 11 of 30 copilot
   sign-in summaries had claims without links, and **5 of the 6** overturned
   verdicts were among them. Incident 5196 is the clearest: three claims, no
   links, wrong verdict. That's the pattern ANALYSIS.md warns about, a
   confident statement nobody checked.
5. **Be honest about the statistics.** With 30 per arm, 6 overturns against
   2 could be chance (Fisher's exact test, two-sided, p ≈ 0.25). The
   unsupported-summary gap, 11 against 3, is less likely to be (p ≈ 0.03).
   The sign-in result is a reason to look closer, not a verdict on the
   copilot.
6. **Endpoint malware: too few to judge.** 12 per arm, medians 20 and 21
   minutes. Its 4 unsupported summaries out of 12 look bad, but 12 is below
   the minimum the team set in advance. More data, not a conclusion.
7. **What none of this shows:** what happened to incidents that never came
   back. QA only re-checks the trial. Once the trial ends, a missed escalation
   looks exactly like a correct benign close.

---

## Detection logic

**In plain English.** This isn't a detection for an attacker. It's a check
that a copilot is helping on a given alert type and not quietly trading
accuracy for speed.

- Keep trial incidents created between Monday 2 November 00:00 and Monday
  23 November 00:00 Sydney time, that have a QA verdict.
- For each alert type and arm, work out the median triage time, the overturn
  rate and the share of summaries with unsupported claims.
- Skip any alert type with fewer than **15** reviewed incidents in either
  arm.
- Flag an alert type when either is true:
  - **SPEED_AT_COST**: the copilot arm is faster, but its overturn rate is
    at least **10 percentage points** higher than control.
  - **UNSUPPORTED**: more than **20%** of copilot-arm summaries make claims
    without evidence links.

**KQL (Microsoft Sentinel / Log Analytics).** `NWCopilotTrial_CL` and its
columns are fictional. The functions (`percentile()`, `countif()`, `maxif()`)
are standard KQL.

```kql
// Copilot trial check: is the copilot buying speed with accuracy, per alert type?
let trialStart     = datetime(2026-11-01T13:00:00Z);  // Mon 2 Nov 00:00 AEDT
let trialEnd       = datetime(2026-11-22T13:00:00Z);  // Mon 23 Nov 00:00 AEDT
let minPerArm      = 15;     // don't judge below this many reviewed incidents per arm
let maxOverturnGap = 0.10;   // copilot overturn rate may exceed control by less than this
let maxUnsupported = 0.20;   // share of copilot summaries with unlinked claims
NWCopilotTrial_CL
| where TimeGenerated >= trialStart and TimeGenerated < trialEnd
| where isnotempty(QAVerdict)                                    // reviewed only
| summarize n           = count(),
            MedianMin   = percentile(TriageMinutes, 50),
            Overturned  = countif(AnalystVerdict != QAVerdict),
            Missed      = countif(AnalystVerdict == "Benign" and QAVerdict == "Malicious"),
            Unsupported = countif(EvidenceLinks < ClaimsInSummary)
    by AlertType, Arm
| extend OverturnRate = todouble(Overturned) / n, UnsupportedRate = todouble(Unsupported) / n
| summarize nCopilot     = maxif(n, Arm == "Copilot"),         nControl     = maxif(n, Arm == "Control"),
            MedCopilot   = maxif(MedianMin, Arm == "Copilot"), MedControl   = maxif(MedianMin, Arm == "Control"),
            OverCopilot  = maxif(OverturnRate, Arm == "Copilot"), OverControl = maxif(OverturnRate, Arm == "Control"),
            MissedCopilot = maxif(Missed, Arm == "Copilot"),   MissedControl = maxif(Missed, Arm == "Control"),
            UnsupCopilot = maxif(UnsupportedRate, Arm == "Copilot")
    by AlertType
| where nCopilot >= minPerArm and nControl >= minPerArm
| extend TimeSaving   = 1 - todouble(MedCopilot) / MedControl,
         OverturnGap  = OverCopilot - OverControl
| extend SpeedAtCost  = MedCopilot < MedControl and OverturnGap >= maxOverturnGap,
         Unsupported  = UnsupCopilot > maxUnsupported
| where SpeedAtCost or Unsupported
| project AlertType, nCopilot, nControl, MedCopilot, MedControl, TimeSaving,
          OverCopilot, OverControl, OverturnGap, MissedCopilot, MissedControl, UnsupCopilot,
          SpeedAtCost, Unsupported
```

I ran the same logic in Python over 168 generated rows that reproduce the
tables above, including the three unreviewed incidents and incident 5268's
time-zone edge:

```
raw rows 168
in window & reviewed 164
Reported phishing    nC=40 nX=40 medC=6 medX=14 saving=57% overC=2/40=5.0% overX=4/40=10.0% gap=-5.0pts unsupC=3=7.5% speedAtCost=False unsupported=False -> no row
Suspicious sign-in   nC=30 nX=30 medC=9 medX=17 saving=47% overC=6/30=20.0% overX=2/30=6.7% gap=13.3pts unsupC=11=36.7% speedAtCost=True unsupported=True -> ROW
Endpoint malware     nC=12 nX=12 medC=20 medX=21 saving=5% overC=1/12=8.3% overX=1/12=8.3% gap=0.0pts unsupC=4=33.3% speedAtCost=False unsupported=False -> no row
output rows 1
```

**1 row**: suspicious sign-in, with both flags. Phishing is excluded because
its copilot arm is faster *and* overturned less, with 7.5% unsupported.
Endpoint malware is excluded by the minimum of 15 per arm, even though its
33.3% unsupported rate would otherwise trip UNSUPPORTED.

**What I verified and what I didn't.** The table and every row are
fictional. `percentile()` in KQL returns an estimate of the nearest-rank
percentile
([Microsoft Learn](https://learn.microsoft.com/en-us/kusto/query/percentiles-aggregation-function?view=microsoft-fabric)),
so the Python check uses nearest rank too; on small groups like these it
should match, but I haven't run the query against a live workspace.

**Tuning note:**

- **The thresholds are choices, not statistics.** A 10-point gap on 30
  incidents per arm can be noise, as point 5 shows. The rule decides what
  gets a human review. If you want a significance test, decide on it before
  the trial, not after a result you dislike.
- **Weight the direction.** Over-escalating wastes time; missing an
  escalation is the expensive mistake. A stricter rule flags any alert type
  where `MissedCopilot` is higher than `MissedControl` by two or more,
  whatever the overall overturn rate.
- **Don't reward the copilot for skipping links.** If analysts learn that
  unsupported summaries get flagged, the easy fix is writing fewer claims.
  Read a sample of summaries as well as counting them.
- **Pick the response before you see the result.** For sign-ins, the options
  are a narrower use (the copilot drafts, but sign-in verdicts need a linked
  query for every "no other activity" claim), more trial data, or switching
  it off for that alert type. Removing the control arm because the team
  likes the tool isn't one of them.
- **Keep sampling after the trial.** Day 21's weekly health check and
  ANALYSIS.md's QA sampling of closed alerts keep going once the copilot is
  everywhere; the trial only tells you where it started.

There's no ATT&CK or ATLAS mapping today: this is a measurement problem, not
an attack. Day 24 covers the attack version, a copilot fed injected text
through the logs it summarises.

---

## Your turn

1. The live-operations paper only counted incidents resolved within 12
   hours. Describe a way a copilot could make Northwind's SOC slower that
   this filter would hide. What one extra measure would reveal it?
2. Redesign the sign-in workflow so the copilot still saves time but can't
   close an incident on an unsupported claim. Which claims must carry a
   linked query, and who checks?
3. In the phishing study, most of the gain came from prioritising the queue
   rather than the AI's verdicts. Name a non-AI way Northwind could get some
   of that benefit, and how you'd test whether it does.
4. Write the one-paragraph rule for ending the trial early: what result
   would make you stop and switch the copilot off for an alert type, before
   the three weeks are up?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Bono, Grana and Xu (Microsoft, vendor research): [Generative AI and Security Operations Center Productivity: Evidence from Live Operations](https://arxiv.org/html/2411.03116v2)
- Bono and Xu (Microsoft, vendor research): [Randomized Controlled Trials for Security Copilot for IT Administrators](https://arxiv.org/html/2411.01067v2)
- Bono (Microsoft, vendor research): [Randomized Controlled Trials for Phishing Triage Agent](https://arxiv.org/html/2511.13860v1)
- Becker, Rush, Barnes and Rein (METR): [Measuring the Impact of Early-2025 AI on Experienced Open-Source Developer Productivity](https://arxiv.org/abs/2507.09089)
- Microsoft Learn: [Security Copilot for Microsoft 365 E5 and E7 customers](https://learn.microsoft.com/en-us/copilot/security/security-copilot-inclusion) · [Access the Security Copilot audit log](https://learn.microsoft.com/en-us/copilot/security/audit-log) · [percentile(), percentiles()](https://learn.microsoft.com/en-us/kusto/query/percentiles-aggregation-function?view=microsoft-fabric)
- This log: [ANALYSIS.md, What the evidence supports](../ANALYSIS.md#what-the-evidence-supports) · [Day 19](2026-11-21-logging-llm-apps-detect-abuse.md) (logging LLM apps) · [Day 21](2026-11-23-ai-ids-base-rates-precision-drift.md) (precision, labels and the weekly health check) · October: [Day 17, alert triage](https://github.com/vipercipher/soc-lab-beginner/blob/main/learning-log/2026-10-27-alert-triage.md)

⬅️ [Learning log index](README.md) · ➡️ Day 23: Hallucination in playbooks: verifying AI output (25 Nov)
