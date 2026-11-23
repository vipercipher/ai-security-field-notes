# Day 21 — AI-Powered IDS: Base Rates, Precision and Drift

📅 23 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Yesterday ended with a promise: base rates and drift in detail. They're the
two questions that decide whether an ML intrusion detection system (IDS)
helps the SOC or buries it, and both are easy to skip when a vendor shows a
"99% accurate" slide.

The base rate problem isn't new. Stefan Axelsson set it out in 1999, using
Bayes' theorem, and concluded that "the factor limiting the performance of an
intrusion detection system is not the ability to identify behavior correctly
as intrusive, but rather its ability to suppress false alarms"
([Axelsson, ACM TISSEC 2000](https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf)).
Twenty-three years later, Arp et al. still found the base rate fallacy among
the pitfalls in papers at top security venues
([USENIX Security 2022](https://www.usenix.org/system/files/sec22-arp.pdf)).

Drift is the other half. A model is trained on the past and judged on the
present, and a network changes every week: new software, new suppliers, new
log pipelines. ANALYSIS.md puts it in one line: anomaly detection reports
"different", which isn't the same as "bad". Today is about doing the
arithmetic before you buy, and measuring the model after you deploy it.

---

## The concept

### Four numbers, and why "accuracy" hides them

Every detector, ML or not, sorts events into four boxes.

| | **Really malicious** | **Really benign** |
|---|---|---|
| **Alert** | True positive (TP) | False positive (FP) |
| **No alert** | False negative (FN) | True negative (TN) |

From those come the measures people quote:

| Measure | Formula | Question it answers | Who quotes it |
|---|---|---|---|
| **Detection rate** (recall, TPR) | TP / (TP + FN) | Of the attacks, how many did it catch? | Vendors, papers |
| **False positive rate** (FPR) | FP / (FP + TN) | Of the benign events, how many did it flag? | Vendors, papers |
| **Precision** | TP / (TP + FP) | Of the alerts, how many were real? | **The analyst working the queue** |
| **Accuracy** | (TP + TN) / everything | How many events did it get right? | Slides |

Accuracy is almost useless here. If 1 event in 100,000 is malicious, a
detector that **never alerts** is 99.999% accurate. Arp et al. make the
same point: a single number such as accuracy is "typically insufficient",
and even ROC curves can look excellent on imbalanced data while precision
tells the real story. They recommend precision and recall, and "discussing
false positives in relation to the base rate".

### The base rate, worked through

Precision depends on three things: the detection rate, the false positive
rate, and the **base rate**, the share of events that are actually malicious.
Hold the detector fixed (catches 99%, wrongly flags 0.1% of benign events),
score 10 million events a day, and change only the base rate:

| Base rate | Malicious events | True positives | False positives | **Precision** | Real alerts |
|---|---|---|---|---|---|
| 1 in 100 | 100,000 | 99,000 | 9,900 | **90.9%** | about 10 in 11 |
| 1 in 1,000 | 10,000 | 9,900 | 9,990 | **49.8%** | about 1 in 2 |
| 1 in 10,000 | 1,000 | 990 | 9,999 | **9.0%** | about 1 in 11 |
| 1 in 100,000 | 100 | 99 | 10,000 | **1.0%** | about 1 in 100 |

The last row is the example in ANALYSIS.md. The model didn't get worse from
row to row. The *environment* got cleaner, and precision collapsed. That's
why a vendor's precision on a lab dataset, where attacks might be 1 in 10 of
the samples, tells you little about precision on your network.

The false positive rate is the lever. At 1 in 100,000, cutting it from 0.1%
to 0.01% takes precision from about 1% to 9%; cutting it to 0.001% takes it
to about 50%. Axelsson's version of the same sum was a site with about a
million audit records a day and one or two intrusion attempts, and he
concluded the false alarm rate had to be "less than 1/100,000 per 'event'".

### Where the optimistic numbers come from

The research literature explains most of the gap between a demo and a
deployment. These are findings from peer-reviewed papers, not vendor
research.

| Problem | What it means | Source |
|---|---|---|
| **Temporal snooping** | Training and test data mixed across time, so the model has effectively seen the future | Arp et al. call it a common pitfall, because "the underlying distributions in many security-related problems are under continuous change" |
| **Temporal and spatial bias** | Time splits that couldn't happen in real life, and test data that doesn't look like a real deployment | [TESSERACT (Pendlebury et al., USENIX Security 2019)](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury): published Android malware F1 scores "of up to 0.99" were "commonly inflated" by these two biases |
| **Threshold picked on the test set** | The cut-off score was tuned on the data used to report results | Arp et al. note an IDS threshold chosen this way "can be hard to select" in practice, "due the diversity of real-world traffic" |
| **Lab-only evaluation** | Closed-world tests with "no consideration of non-stationarity" | Arp et al.; Sommer and Paxson (Day 20) made the same argument in 2010 |

So, as judgement rather than a rule, the questions I'd put to a vendor are:

| Ask | Why |
|---|---|
| What was the base rate in your test data? | If it's far above yours, precision won't transfer |
| Was the test data later in time than the training data? | If not, the number includes temporal snooping |
| What precision do existing customers see, per detection, after 90 days? | Precision in production, after drift has had time to act |
| How do we get labels back to you, and how often is the model retrained? | No feedback loop means drift is your problem alone |
| Can we run it in our network, alert-only, for a month first? | Your base rate is the only one that counts |

### Drift: the model is fine, the world moved

"Drift" is used loosely. Separating the kinds helps, because they show up in
different places and some of them don't show up at all.

| Kind | What changes | Northwind example | Where you'd see it |
|---|---|---|---|
| **Data drift** | The inputs: new software, new traffic patterns | A new backup agent checks in every five minutes, which looks like beaconing | Alert volume jumps; precision falls |
| **Concept drift** | What attacks look like | Attackers move command and control to a popular cloud service the model treats as normal | **Nowhere in the alert data.** Recall falls silently |
| **Pipeline breakage** | A log source, field or parser | DNS resolvers migrate and the query name lands in a different field | A detection goes quiet |
| **Label drift** | How analysts close incidents | A swamped team stops closing, or closes faster with less care | Your precision measurement itself becomes unreliable |
| **Adversarial pressure** | Attackers shape their activity to the model | Evasion: MITRE ATLAS [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015). Poisoning the baseline: Days 18 and 20 | Usually nowhere, until an incident |

Pipeline breakage isn't drift in the textbook sense, but it produces the same
symptom, and a quiet detection is worth checking for an attacker too: MITRE
ATT&CK's [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)
lists intrusion detection systems and logging agents among the things
adversaries tamper with.

The uncomfortable row is concept drift. Every metric in your SIEM is built
from alerts that fired. A model that stops recognising a new technique
produces fewer alerts, which looks like *good* news. Only seeded test
activity, or a hunt that doesn't rely on the model, catches that. ANALYSIS.md
recommends both.

### Measuring it with what you already have

Microsoft Sentinel records how each incident was closed. The
[SecurityIncident table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident)
has `Classification`, `CreatedTime`, `ClosedTime`, `Title` and
`RelatedAnalyticRuleIds`, among others. The close options in the portal are
**True Positive** (suspicious activity), **Benign Positive** (suspicious but
expected), **False Positive** (incorrect alert logic or incorrect data) and
**Undetermined**
([Microsoft Learn](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage)),
stored as `TruePositive`, `BenignPositive`, `FalsePositive` and `Undetermined`.

Two details matter for the query:

- **One incident, many rows.** "Every time you create or update an incident,
  a new log entry will be added to the table", so you keep the latest version
  with `summarize arg_max(TimeGenerated, *) by IncidentNumber`
  ([Microsoft Learn: incident metrics](https://learn.microsoft.com/en-us/azure/sentinel/manage-soc-with-incident-metrics)).
- **Is a benign positive noise?** For an analyst's time, yes: the alert was
  correct about the behaviour and nothing needed doing. Microsoft's own
  noise-ratio sample counts `BenignPositive` alongside `FalsePositive` as
  noise
  ([Microsoft Learn sample](https://learn.microsoft.com/en-us/entra/global-secure-access/scripts/powershell-test-alert-noise-ratio)).
  I do the same below, so "precision" here means TP / (TP + BP + FP), with
  Undetermined and still-open incidents left out.

---

## Sample logs

Everything is fictional. Northwind runs a network detection product (a
fictional "NDR") whose ML scores feed four Sentinel analytics rules, all
named `NW-ML …`. The review runs on Monday 23 November and checks the
**week starting Monday 16 November** in Sydney time (AEDT, UTC+11), against
the four weeks before it (19 October to 15 November).

**Raw `SecurityIncident` rows** (real column names, fictional rows, times in
UTC; five of the 325 rows in the sample, which cover 168 incidents):

```
TimeGenerated         IncidentNumber  Title                         Severity  Status  Classification  CreatedTime
2026-11-15T13:10:04Z  4471            NW-ML Beaconing score         Medium    New     -               2026-11-15T13:10:02Z
2026-11-15T16:22:40Z  4471            NW-ML Beaconing score         Medium    Closed  BenignPositive  2026-11-15T13:10:02Z
2026-11-17T23:41:19Z  4498            NW-ML Beaconing score         Medium    Closed  TruePositive    2026-11-17T04:55:37Z
2026-11-18T02:03:51Z  4502            NW-ML Lateral movement score  High      New     -               2026-11-18T02:03:49Z
2026-11-18T02:09:12Z  4503            NW-ML Beaconing score         Medium    New     -               2026-11-18T02:09:10Z
```

**Per rule, per week**, after keeping the latest row of each incident and
grouping by the Sydney week the incident was *created* in. Each cell is
TP / BP / FP / Undetermined / still open:

```
Rule                          19 Oct      26 Oct      02 Nov      09 Nov      | 16 Nov (target)
NW-ML Beaconing score         1/3/5/0/0   0/4/6/1/0   1/2/5/0/0   0/3/7/0/0   | 1/38/12/2/3
NW-ML DNS tunnelling score    0/1/2/0/0   1/0/2/0/0   0/1/1/0/0   0/0/2/0/0   | 0/0/0/0/0
NW-ML Rare outbound volume    1/2/4/0/0   0/2/5/0/0   1/1/4/0/0   0/3/5/0/0   | 1/2/4/0/0
NW-ML Lateral movement score  0/2/3/0/1   1/1/3/0/0   0/2/2/0/1   0/1/4/0/0   | 0/1/1/0/6
```

Context (fictional, and none of it is in the incident table):

- Change CHG-4519 rolled a new backup agent out to staff laptops from Monday
  16 November. It checks in with `backup.example` every five minutes.
- Change CHG-4507 migrated Northwind's DNS resolvers on Friday 13 November.
  The new resolvers log the query name in a different field.
- The team spent most of the week of 16 November on beaconing incidents.

---

## What to look for

1. **Count first.** 4 rules, 168 incidents: 97 in the four baseline weeks
   and 71 in the target week (56 + 0 + 7 + 8). The raw table has 325 rows
   because every incident has a "New" row and the 157 closed ones also have a
   "Closed" row. Count rows instead of incidents and the beaconing rule looks
   almost twice as busy as it is.
2. **Bucket in Sydney time.** Incident 4471 was created at 13:10 UTC on
   Sunday 15 November, which is 00:10 on Monday 16 November in Sydney. It
   belongs to the target week. Bucket by UTC and it slips into the week before.
3. **Beaconing: classic data drift.** 56 incidents against a baseline
   average of 9.5 a week, about 5.9 times normal. 38 of them are benign
   positives, matching the backup agent rollout. Precision fell from 5.4%
   (2 of 37 classified in the baseline) to 2.0% (1 of 51). The model is
   doing exactly what it was built to do: regular check-ins *are* beacon-like.
   "Different, not bad", 38 times. Note the one true positive is still in
   there, now hidden among 50 that aren't.
4. **DNS tunnelling: the silence is the finding.** Two or three incidents
   every week, then zero, starting the week after the resolver migration.
   No alerts looks like good news. It's more likely a broken feature
   pipeline, and that has to be confirmed rather than assumed.
5. **Lateral movement: you can't measure it this week.** 8 incidents, only 2
   closed, 6 still open. Its 0% precision means nothing on two labels. One
   drifted model's flood has starved another model of analyst attention:
   label drift caused by data drift.
6. **Rare outbound volume: steady.** 7 incidents, the same as its average.
   Its precision *rose* from 7.1% to 14.3%, but that's one true positive out
   of seven. On numbers this small, precision swings wildly from week to week,
   which is why the rule below needs at least 10 classified incidents before
   it judges precision.
7. **What none of this shows:** recall. If the beaconing model has stopped
   recognising a new kind of command and control, nothing in this table
   changes.

---

## Detection logic

**In plain English.** This isn't a detection for an attacker. It's a weekly
health check on the detections themselves.

- Keep the latest version of each incident. Keep only the ML rules
  (`Title` starts with `NW-ML `).
- Bucket each incident into a Monday-to-Sunday week by its **creation** time
  in Sydney.
- For each rule, compare the target week with the average of the four
  weeks before it. Weeks with no incidents count as zero.
- Flag a rule when any of these is true:
  - **SILENT**: no incidents this week, but it averaged **2 or more** a week.
  - **VOLUME**: **10 or more** incidents and at least **2 ×** its weekly average.
  - **PRECISION**: at least **10** classified incidents and precision below
    **half** of its baseline precision.
  - **UNMEASURED**: under **70%** of this week's incidents are classified, so
    precision can't be trusted yet.

**KQL (Microsoft Sentinel).** `SecurityIncident` is a real Sentinel table and
the columns are from Microsoft's table reference. The rule names and rows
are fictional.

```kql
// Weekly health check for ML detections: volume, precision and silence, per rule
let tz            = "Australia/Sydney";
let weekStart     = datetime(2026-11-16);  // Monday of the week to check, Sydney date
let baseWeeks     = 4;
let minIncidents  = 10;                    // VOLUME needs at least this many
let minClassified = 10;                    // PRECISION needs at least this many labels
let minLabelRate  = 0.7;                   // below this, precision isn't trustworthy yet
let incidents = SecurityIncident
    | where TimeGenerated > ago(90d)
    | summarize arg_max(TimeGenerated, *) by IncidentNumber          // latest version of each incident
    | where Title startswith "NW-ML "
    | extend Week = bin_at(datetime_utc_to_local(CreatedTime, tz), 7d, weekStart)
    | where Week >= weekStart - baseWeeks * 7d and Week <= weekStart;
let weekly = incidents
    | summarize Total = count(),
                TP = countif(Classification == "TruePositive"),
                BP = countif(Classification == "BenignPositive"),
                FP = countif(Classification == "FalsePositive")
        by Title, Week;
let baseline = weekly
    | where Week < weekStart
    | summarize BaseTotal = sum(Total), BaseTP = sum(TP), BaseClassified = sum(TP + BP + FP) by Title
    | extend BaseAvg = todouble(BaseTotal) / baseWeeks,
             BasePrecision = iff(BaseClassified > 0, todouble(BaseTP) / BaseClassified, real(null));
let current = weekly
    | where Week == weekStart
    | project Title, Total, TP, Classified = TP + BP + FP;
baseline
| join kind=leftouter current on Title
| extend Total = coalesce(Total, 0), TP = coalesce(TP, 0), Classified = coalesce(Classified, 0)
| extend Ratio     = Total / BaseAvg,
         LabelRate = iff(Total > 0, todouble(Classified) / Total, real(null)),
         Precision = iff(Classified > 0, todouble(TP) / Classified, real(null))
| extend Silent     = Total == 0 and BaseAvg >= 2,
         Volume     = Total >= minIncidents and Ratio >= 2,
         PrecDrop   = Classified >= minClassified and Precision < BasePrecision / 2,
         Unmeasured = Total > 0 and LabelRate < minLabelRate
| where Silent or Volume or PrecDrop or Unmeasured
| project Title, Total, BaseAvg, Ratio, Classified, LabelRate, Precision, BasePrecision,
          Silent, Volume, PrecDrop, Unmeasured
| order by Total desc
```

I ran the same logic in Python over 325 generated rows that reproduce the
weekly table, including the duplicate versions and incident 4471's
time-zone edge:

```
raw rows 325 incidents 168
edge incident week (Sydney): 2026-11-16  UTC-week would be: 2026-11-09
NW-ML Beaconing score          Total= 56 BaseAvg= 9.50 Ratio=5.89 Classified= 51 LabelRate=0.91 Prec=2.0%   BasePrec=5.4%  silent=False volume=True precision=True unmeasured=False -> ROW
NW-ML DNS tunnelling score     Total=  0 BaseAvg= 2.50 Ratio=0.00 Classified=  0 LabelRate=     Prec=       BasePrec=10.0%  silent=True volume=False precision=False unmeasured=False -> ROW
NW-ML Rare outbound volume     Total=  7 BaseAvg= 7.00 Ratio=1.00 Classified=  7 LabelRate=1.00 Prec=14.3%  BasePrec=7.1%  silent=False volume=False precision=False unmeasured=False -> no row
NW-ML Lateral movement score   Total=  8 BaseAvg= 5.25 Ratio=1.52 Classified=  2 LabelRate=0.25 Prec=0.0%   BasePrec=5.3%  silent=False volume=False precision=False unmeasured=True -> ROW
output rows 3
```

**3 rows**: beaconing (VOLUME and PRECISION), DNS tunnelling (SILENT) and
lateral movement (UNMEASURED). Rare outbound volume is excluded: its volume
is normal and seven labels are under the minimum for a precision judgement.
The DNS rule only appears because the query starts from the **baseline**
side of the join. Start from the current week and a rule with zero incidents
has no row to find.

**What I verified and what I didn't.** Column names are from the
[SecurityIncident reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident),
the classification strings from Microsoft's
[noise-ratio sample](https://learn.microsoft.com/en-us/entra/global-secure-access/scripts/powershell-test-alert-noise-ratio),
and the one-row-per-update behaviour and `arg_max` pattern from the
[incident metrics page](https://learn.microsoft.com/en-us/azure/sentinel/manage-soc-with-incident-metrics).
`bin_at()` and `datetime_utc_to_local()` are standard KQL functions. I
haven't run this against a live workspace, only as the Python equivalent.
The `NW-ML` rules, the NDR and every row are fictional.

**Tuning note:**

- **Run it mid-week, not Monday morning.** Incidents from last Sunday won't
  be closed yet, so everything looks UNMEASURED. Running on Wednesday for the
  week before is a trade-off: two days later, but on real labels.
- **Group by rule ID, not title.** Titles can be edited, and some rules put
  entity names in the title. `RelatedAnalyticRuleIds` is the sturdier key; I
  used `Title` because it's readable.
- **Feed it change tickets.** The beaconing flood had an explanation sitting
  in CHG-4519. A watchlist of changes joined by week turns "VOLUME" into
  "VOLUME, probably CHG-4519", which is still a question but a faster one.
- **Don't fix VOLUME with a blanket exclusion.** Excluding `backup.example`
  kills the flood, and also gives any attacker using the same service a
  pass. Prefer a narrow exclusion (signed agent, expected interval, expected
  destination) and record when it should be reviewed.
- **SILENT needs a canary.** A rule that averages 2.5 incidents a week can
  have a quiet week by chance. A small, harmless, scheduled test event that
  the rule should always catch tells you the pipeline still works. ANALYSIS.md
  calls this seeding known-bad test activity.
- **Expect label quality to vary.** A precision figure is only as good as
  the closing discipline behind it. If the team closes floods in bulk, the
  measurement drifts with them.

ATT&CK mapping (for the SILENT case):
[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/).
ATLAS: [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015).

---

## Your turn

1. Redo the base rate arithmetic for Northwind's NDR: it scores 2 million
   flows a day, about 1 in 500,000 is malicious, it catches 95%, and its
   false positive rate is 0.01%. How many alerts a day, and what precision?
   The team can work about 40 ML alerts a day. What false positive rate would
   fit that?
2. The beaconing rule's one true positive sat among 50 benign and false
   positives. Write a tuning change for the backup agent that would remove
   most of the 38 benign positives, then name exactly what an attacker
   would need to do to hide inside your exclusion.
3. Design a canary for the DNS tunnelling rule: a harmless, scheduled
   lookup pattern under `northwind-example.com` that the rule should always
   flag. How do you stop the canary from being worked as a real incident, and
   how do you stop an attacker copying it to hide?
4. The query counts benign positives as noise. Argue the other side: when
   would you want a high benign positive count from an ML IDS? What would you
   change in Northwind's closing guidance so the classification tells you
   more?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Axelsson: [The Base-Rate Fallacy and the Difficulty of Intrusion Detection](https://www.profsandhu.com/cs6393_s20/p186-axelsson.pdf) (ACM TISSEC, 2000; first presented at ACM CCS 1999)
- Arp et al.: [Dos and Don'ts of Machine Learning in Computer Security](https://www.usenix.org/system/files/sec22-arp.pdf) (USENIX Security 2022: data snooping, inappropriate performance measures, the base rate fallacy, lab-only evaluation)
- Pendlebury et al.: [TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time](https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury) (USENIX Security 2019) · [arXiv version](https://arxiv.org/abs/1807.07838)
- Microsoft Learn: [SecurityIncident table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/securityincident) · [Manage your SOC with incident metrics](https://learn.microsoft.com/en-us/azure/sentinel/manage-soc-with-incident-metrics) (one row per update) · [Navigate, triage and manage incidents](https://learn.microsoft.com/en-us/azure/sentinel/incident-navigate-triage) (close classifications) · [Calculate the alert noise ratio](https://learn.microsoft.com/en-us/entra/global-secure-access/scripts/powershell-test-alert-noise-ratio) (a weekly noise check, in PowerShell and KQL)
- MITRE ATLAS: [AML.T0015 Evade AI Model](https://atlas.mitre.org/techniques/AML.T0015) · MITRE ATT&CK: [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/)
- This log: [ANALYSIS.md, ML detection and the arithmetic of alert fatigue](../ANALYSIS.md#ml-detection-and-the-arithmetic-of-alert-fatigue) · [Day 18](2026-11-20-data-poisoning-training-rag-memory.md) (poisoning) · [Day 20](2026-11-22-ml-threat-hunting-ueba-baselines.md) (baselines, Sommer and Paxson) · October: [Day 17, alert triage](https://github.com/vipercipher/soc-lab-beginner/blob/main/learning-log/2026-10-27-alert-triage.md)

⬅️ [Learning log index](README.md) · ➡️ [Day 22: Incident response copilots: measuring real value (24 Nov)](2026-11-24-ir-copilots-measuring-real-value.md)
