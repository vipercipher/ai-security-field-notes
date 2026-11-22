# Day 20 — ML Threat Hunting: Anomalies, UEBA and Baselines

📅 22 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Part 3 starts with the oldest promise of AI in the SOC: learn what normal
looks like and flag what doesn't, so you catch the attacker who uses valid
accounts and built-in tools and never trips a signature. It's a reasonable
promise. Most of this month's attacks (the help desk reset on Day 05, the
inbox rules on Day 07, the remote worker on Day 09) end with a real account
doing real things, and the only thing wrong is that it's *unusual*.

The government guidance agrees with the idea and is blunt about the gap.
The joint guide on living off the land, co-authored by ASD's ACSC, says many
organisations lack "established baselines" and that this "makes it difficult
for network defenders to discern legitimate behavior from malicious
behavior". It recommends using machine learning "to compare current
activities against established behavioral baselines" and to "leverage user
and entity behavior analytics (UEBA)"
([CISA, NSA, FBI, ASD's ACSC and others, February 2024](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf)).

ANALYSIS.md adds the caution that frames today: anomaly detection reports
"different", which isn't the same as "bad". This entry is about what a
baseline actually is, what a UEBA product gives you, and why the hunt still
needs a person who knows the business.

---

## The concept

### A baseline is a question, not a fact

"Is this normal?" only means something once you've answered four smaller
questions. Each answer is a design choice, and each one can hide an attack.

| Choice | Example | What goes wrong if you get it wrong |
|---|---|---|
| **Normal for whom?** | This user, their peers, the whole organisation | A user's own history can't judge their first week. The organisation's average hides a single odd account |
| **Measured how?** | Count of downloads per day, distinct countries, first-time actions | You can only find what you measure. A daily count misses a burst that stays under it |
| **Over what window?** | Last 10, 30 or 180 days | Too short and last week's attack becomes "normal". Too long and a real change in someone's job alerts for months |
| **In which time zone, on which days?** | Sydney working days, not UTC calendar days | A UTC day cuts a Sydney working day in half (AEDT is UTC+11), and weekends drag the average down |

The third row is the one attackers exploit. A rolling baseline learns from
whatever happened recently, including anything an attacker did slowly enough.
MITRE ATLAS lists poisoning an ML system's training data as a technique in its
own right ([AML.T0020 Training Data Poisoning](https://atlas.mitre.org/techniques/AML.T0020)).
A UEBA baseline is training data, and nobody labels it.

### What a UEBA product actually gives you

Using Microsoft Sentinel as the worked example because its documentation is
specific. Other SIEMs have equivalents with different names.

| Table | What's in it | Useful for |
|---|---|---|
| `BehaviorAnalytics` | One row per enriched event, with `InvestigationPriority` (**0–10**) and an `ActivityInsights` bag of true/false flags | Triage of single events: "is this login odd for this person?" |
| `Anomalies` | `AnomalyScore` (**0–1**) from batch ML over many events | Patterns over time |
| `UserPeerAnalytics` | Each user's top 20 peers, ranked from group memberships using TF-IDF | "What do people like this user normally do?" |
| `IdentityInfo` | Profile data from Entra ID: department, manager, roles | The context a raw log doesn't have |

([Microsoft Learn: UEBA in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics))

The part worth reading slowly is the
[UEBA reference](https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference).
Every `ActivityInsights` flag has its own lookback, and they're not the same:

| Flag (examples) | Baseline |
|---|---|
| `FirstTimeUserPerformedAction`, `FirstTimeUserAccessedResource` | 180 days |
| `FirstTimeUserConnectedFromCountry`, `CountryUncommonlyConnectedFromAmongPeers` | 90 days |
| `FirstTimeUserConnectedFromDevice`, `FirstTimeUserConnectedViaISP` | 30 days |
| `CountryUncommonlyConnectedFromByUser`, `ActionUncommonlyPerformedByUser` | 10 days |
| `UncommonHighVolumeOfOperations` | 7 days |

Read the 10-day rows with the attacker in mind. "Uncommon for this user"
forgets after about two weeks, so an attacker who keeps coming back from the
same place becomes common. The 90- and 180-day "first time" flags remember
longer, which is why they're more useful for spotting a return visit.

Microsoft's own example of how the two scores differ is a good lesson in
reading them: a user doing an Azure operation for the first time gets a
**high** investigation priority, because it's a first, but a **low** anomaly
score, because "occasional first-time Azure actions are common and not
inherently risky". Neither score is a verdict. Both tell you where to look.

### What the research says about anomaly detection

Two papers are worth knowing by name, because they explain most of the
disappointment people have with "AI that learns normal".

- **Sommer and Paxson (IEEE S&P 2010)** argue that machine learning is good
  at "finding activity that is similar to something previously seen" and
  much worse at spotting genuinely new things. They name a **semantic gap**:
  the model says "this didn't match the profile", and an analyst still has to
  work out "What does it mean?". They also warn about "a failure to examine
  whether simpler, non-machine learning approaches might work equally well"
  ([paper](https://www.umiacs.umd.edu/~tdumitra/courses/ENEE657/Fall19/papers/Sommer10.pdf)).
- **Arp et al. (USENIX Security 2022)** reviewed 30 papers from top security
  conferences and found ten recurring pitfalls, including *sampling bias*,
  *inappropriate baselines* (not comparing against simpler methods), the
  *base rate fallacy* and *lab-only evaluation*
  ([paper](https://www.usenix.org/system/files/sec22-arp.pdf)).

The practical reading, and this is judgement: before trusting a clever
model, check whether a per-user percentile and a person who knows the
business would find the same thing. Often they would, and you can explain
their answer. Tomorrow (Day 21) covers base rates and drift in detail.

### UEBA flags vs your own baseline query

| | **UEBA flags and scores** | **Your own baseline (KQL below)** |
|---|---|---|
| Setup | Turn it on, connect sources | Write, test and maintain it |
| What it measures | Microsoft's chosen features | Exactly what you choose, such as downloads per working day |
| Explainable? | Flags are clear; scores less so | Fully: you can show the arithmetic |
| Business calendar | Not yours | Your time zone, your working days |
| Weakness | Fixed windows you can't change; covers only connected sources | Only as good as your feature choice; easy to get subtly wrong |

My view, and it's judgement: use both, and treat agreement between them as
the signal. One odd number is a lead. Two independent odd things about the
same account on the same day is a case.

---

## Sample logs

Everything is fictional. Northwind is in Sydney, so days are **Sydney
working days** (AEDT, UTC+11). The hunt runs on Saturday 21 November and
looks at **Friday 20 November**. User names are shortened from
`name@northwind-example.com`.

**Daily SharePoint and OneDrive downloads** (`OfficeActivity`, `Operation ==
"FileDownloaded"`), counted per Sydney working day. This is what the query's
`make-series` step produces. Weekends are left out. Days with no downloads
are **0**, not missing:

```
UserId              06   09   10   11   12   13   16   17   18   19  | 20 (target)
a.nguyen            14    9   16   11   13   12   15   10   18   14  |    21
k.osei              22   25   19   30   24   28   21   26   23   27  |   310
m.lee                8    9    7   10   12   18   26   34   41   45  |    48
r.patel              6    0    8    5    7    0    6    9    4    7  |   212
svc-intranet-index 1480 1502 1495 1510 1488 1499 1505 1492 1515 1497 |  1510
j.park               0    0    0    0    0    0    0    0   31   40  |    64
```

**UEBA** (`BehaviorAnalytics`, real field names, fictional rows; times in
UTC; the `ActivityInsights` column shows only the flags that were true):

```
TimeGenerated         UserPrincipalName  ActivityType  SourceIPAddress  SourceIPLocation  InvestigationPriority  ActivityInsights (true flags)
2026-11-19T21:58:12Z  a.nguyen           LogOn         198.51.100.23    Australia         2                      ISPUncommonlyUsedByUser
2026-11-19T22:15:40Z  k.osei             LogOn         192.0.2.25       Australia         0                      -
2026-11-19T22:30:05Z  j.park             LogOn         192.0.2.31       Australia         3                      FirstTimeUserConnectedFromDevice, FirstTimeUserConnectedViaBrowser
2026-11-19T22:47:51Z  m.lee              LogOn         192.0.2.44       Australia         0                      -
2026-11-19T23:05:10Z  r.patel            LogOn         192.0.2.52       Australia         0                      -
2026-11-20T02:12:33Z  r.patel            LogOn         203.0.113.77     Netherlands       7                      FirstTimeUserConnectedFromCountry, FirstTimeUserConnectedViaISP, CountryUncommonlyConnectedFromAmongPeers
```

Context (fictional, and mostly *not* in the logs):

- `a.nguyen` works in finance and was at home on Friday.
- `k.osei` is in marketing. Change ticket CHG-4471 approved moving brand
  assets to a new asset library on 20 November.
- `m.lee` is an engineer who resigned on 11 November. The last day is 4
  December. HR knows. The SOC doesn't, by default.
- `r.patel` is a contractor. On 19 November the help desk reset their MFA
  after a phone call (the Day 05 scenario). All 212 downloads on Friday came
  from `203.0.113.77` between 13:15 and 13:49 Sydney time.
- `svc-intranet-index` is a third-party search connector that reads documents
  every working day.
- `j.park` started in finance on Wednesday 18 November.

---

## What to look for

1. **Count first.** 6 accounts, 10 baseline working days (6 to 19
   November, weekends left out), one target day. `BehaviorAnalytics` has **6**
   rows from **5** users. The service account has none, because it doesn't
   sign in interactively.
2. **Size isn't the signal, change is.** `svc-intranet-index` downloads about
   1,500 files every day. A fixed rule like "more than 200 downloads a day"
   would fire on it on **all 10** baseline days and on Friday, and fire on
   `k.osei` and `r.patel` too. Against its own history, 1,510 is ordinary.
3. **`r.patel` is the clearest case.** Typical day: 6 downloads. Friday:
   212, about 35 times the median, in 34 minutes, from a new country and ISP.
   UEBA gave that sign-in a priority of **7** with three "first time" or
   "uncommon" flags. Two independent signals on the same account on the same
   day, the day after an MFA reset.
4. **`k.osei` is just as anomalous and almost certainly fine.** 310 against a
   median of 24 is about 13 times normal, and the sign-in is unremarkable
   (priority 0). The change ticket explains it. The baseline can't know about
   tickets. This is "different, not bad".
5. **`j.park` has no baseline to compare with.** Two working days of history,
   and eight zeros before that. Against those zeros, 64 looks infinite.
   UEBA's priority of 3 is the same problem: everything a new starter does
   is a first. The fair comparison is with their peers in finance.
6. **`m.lee` is the one the rule misses.** Downloads climb from about 9 a day
   to 45 over the two weeks after the resignation. Friday's 48
   is four times the baseline median of 12. The rolling baseline has
   already absorbed the climb, and the fence is 109. The sign-ins look
   normal (priority 0). Nothing here proves anything wrong. A departing
   employee may simply be handing over work. It's a question for a human with
   HR context, not a verdict.
7. **`a.nguyen` is ordinary.** 21 downloads is above the median of 13 but
   under the fence of 27. The home ISP flag (priority 2) is the kind of
   low-level UEBA noise a hunt should step over.

---

## Detection logic

**In plain English:**

- For each user, count `FileDownloaded` events per Sydney working day over
  the previous two weeks, with empty days counted as zero.
- Work out the 25th, 50th and 75th percentiles. Flag the target day when it's
  above **P75 + 3 × (P75 − P25)**. That's a Tukey fence with k = 3, the
  "far out" setting. It uses percentiles, not mean and standard deviation, so
  one previous spike doesn't stretch the baseline much.
- Ignore days under **50** downloads, however unusual. A user going from 1 to
  6 isn't worth an analyst's time.
- If the user has fewer than **5** active days in the baseline, don't score
  them. Send them to a peer comparison instead.
- Join the day's highest UEBA `InvestigationPriority` so the analyst sees
  both signals side by side.

**KQL (Microsoft Sentinel).** `OfficeActivity` and `BehaviorAnalytics` are
real Sentinel tables, and the columns used here are in Microsoft's table
references. The rows above are fictional.

```kql
// Hunt: unusual SharePoint/OneDrive download volume per user, against their own working-day baseline
let tz        = "Australia/Sydney";
let target    = datetime(2026-11-20);   // Sydney date to check; in a schedule use startofday(datetime_utc_to_local(now(), tz)) - 1d
let lookback  = 14d;
let k         = 3.0;                    // Tukey "far out" fence
let floorCnt  = 50;                     // ignore small days, however unusual
let minActive = 5;                      // fewer active baseline days = no usable baseline
let downloads = OfficeActivity
    | where TimeGenerated > ago(30d)
    | where Operation == "FileDownloaded"
    | extend UserId = tolower(UserId), LocalTime = datetime_utc_to_local(TimeGenerated, tz);
let baseline = downloads
    | where LocalTime >= target - lookback and LocalTime < target
    | make-series Daily = count() default = 0 on LocalTime from target - lookback to target step 1d by UserId
    | mv-expand Daily to typeof(long), LocalTime to typeof(datetime)
    | where dayofweek(LocalTime) between (1d .. 5d)            // Monday to Friday
    | summarize ActiveDays = countif(Daily > 0), percentiles(Daily, 25, 50, 75) by UserId
    | project UserId, ActiveDays, P25 = percentile_Daily_25, P50 = percentile_Daily_50, P75 = percentile_Daily_75;
let targetDay = downloads
    | where LocalTime >= target and LocalTime < target + 1d
    | summarize Target = count() by UserId;
let ueba = BehaviorAnalytics
    | extend LocalTime = datetime_utc_to_local(TimeGenerated, tz)
    | where LocalTime >= target and LocalTime < target + 1d
    | summarize MaxPriority = max(InvestigationPriority) by UserId = tolower(UserPrincipalName);
targetDay
| join kind=leftouter baseline on UserId
| extend ActiveDays = coalesce(ActiveDays, 0)
| extend Fence = P75 + k * (P75 - P25)
| extend Verdict = case(
      Target < floorCnt,      "",
      ActiveDays < minActive, "COLD START: compare with peers",
      Target > Fence,         "ALERT",
                              "")
| where isnotempty(Verdict)
| join kind=leftouter ueba on UserId
| project UserId, Target, P25, P50, P75, Fence, ActiveDays, MaxPriority, Verdict
| order by Verdict asc, Target desc
```

On the sample, the query returns **3 rows**: 2 alerts and 1 cold start. I ran
the same logic in Python over the six series and the six UEBA rows, using
nearest-rank percentiles and converting the UEBA times to Sydney time:

```
  checked a.nguyen            Target=   21 P25=   11 P50=   13 P75=   15 Fence=   27.0 ActiveDays=10 -> no row
  checked k.osei              Target=  310 P25=   22 P50=   24 P75=   27 Fence=   42.0 ActiveDays=10 -> ALERT
  checked m.lee               Target=   48 P25=    9 P50=   12 P75=   34 Fence=  109.0 ActiveDays=10 -> no row
  checked r.patel             Target=  212 P25=    4 P50=    6 P75=    7 Fence=   16.0 ActiveDays= 8 -> ALERT
  checked svc-intranet-index  Target= 1510 P25= 1492 P50= 1497 P75= 1505 Fence= 1544.0 ActiveDays=10 -> no row
  checked j.park              Target=   64 P25=    0 P50=    0 P75=    0 Fence=    0.0 ActiveDays= 2 -> COLD START: compare with peers
output rows 3
k.osei     Target=310 P50=24 Fence=42 ActiveDays=10 MaxPriority=0 ALERT
r.patel    Target=212 P50=6 Fence=16 ActiveDays=8 MaxPriority=7 ALERT
j.park     Target=64 P50=0 Fence=0 ActiveDays=2 MaxPriority=3 COLD START: compare with peers
static >200 on target: ['k.osei', 'r.patel', 'svc-intranet-index']  svc days >200 in baseline: 10
m.lee frozen fence 16 median 9
```

What it excludes: `a.nguyen` (under the fence), `svc-intranet-index` (huge
but steady), and `m.lee` (under both the fence and the floor). The output
puts `r.patel` and `k.osei` side by side as equal alerts. **The
`MaxPriority` column is what separates them**: 7 against 0. Without the UEBA
join, the analyst would need the change ticket to tell them apart.

**The `m.lee` gap, in numbers.** The last line of the output shows what
happens if the baseline is frozen at the first five working days, before
the climb: the fence drops from 109 to **16**, and 48 would clear it. The
floor of 50 would still hide it. Two settings, each sensible on its own,
together make a slow climb invisible. That's the case for a second, weekly
hunt that compares each user's latest week with a fixed older window, rather
than tightening this one until it's noisy.

**What I verified and what I didn't.** Table and column names come from
Microsoft's references for
[OfficeActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity)
and the [UEBA tables](https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference).
`FileDownloaded` is in the
[Purview audit activities list](https://learn.microsoft.com/en-us/purview/audit-log-activities).
The `make-series` "to" bound is exclusive and `dayofweek()` counts days since
Sunday, both from the KQL docs. `percentiles()` output columns are named
`percentile_<column>_<P>`. KQL's `percentile()` is a **nearest-rank estimate**
using T-Digest, so on real data it may differ slightly from my Python. The
`ActivityType` value and the UEBA rows are illustrative. I haven't run this
against a live workspace, only as the Python equivalent.

**Tuning note:**

- **The sync client isn't counted.** Files pulled down by the OneDrive sync
  app are logged as `FileSyncDownloadedFull`, a separate operation. An
  attacker with a synced laptop wouldn't show up here. Add it, but expect
  noise: a new laptop syncing a team library will look like an exfiltration.
- **Service accounts need their own rule.** `svc-intranet-index` passed
  because it's steady. If it's compromised, the right question is "did it
  touch anything new?", not "did it download more?".
- **Feed the hunt context it can't learn.** Change tickets (`k.osei`) and HR
  leaver dates (`m.lee`) belong in a watchlist joined to this query. MITRE's
  detection strategy for SharePoint collection (DET0500, listed on the
  [T1213.002 page](https://attack.mitre.org/techniques/T1213/002/)) looks
  for "privileged or rarely used accounts" doing bulk access. That's the
  same idea: the account's context changes the meaning of the volume.
- **Fourteen days is short.** It keeps the sample readable. In production
  I'd start with 28 to 30 working days and test whether alerts change.
- **Run it as a hunt before making it a rule.** Look at a month of output,
  record what each row turned out to be, and only then decide whether it's
  worth an alert.

ATT&CK mapping: [T1213.002 Data from Information Repositories: Sharepoint](https://attack.mitre.org/techniques/T1213/002/)
and [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/).

---

## Your turn

1. Rewrite the baseline with `avg()` and `stdev()` instead of percentiles,
   and flag days above mean + 3 standard deviations. Work it out by hand for
   `r.patel` and for `m.lee`. Which user does it treat differently from the
   Tukey fence, and why do two zero days in `r.patel`'s history matter?
2. `j.park` came back as a cold start. Using `UserPeerAnalytics` and
   `IdentityInfo`, sketch how you'd compare a new starter with their top
   peers instead. What could go wrong if the new starter's peer group is
   itself unusual, such as a two-person team?
3. Write the weekly "slow climb" hunt described above: compare each user's
   most recent five working days with a fixed window from three to five weeks
   ago. How would you stop it flagging everyone who just came back from
   leave?
4. The SOC wants HR to share leaver dates so `m.lee`-type cases can be
   reviewed. Write the two-paragraph case for it, and name what the SOC must
   not do with that data. Use the OAIC guidance from Day 19 as your starting
   point.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Advanced threat detection with UEBA in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/identify-threats-with-entity-behavior-analytics) (the tables and the two scores) · [UEBA reference](https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference) (every `ActivityInsights` flag and its baseline in days)
- Microsoft Learn: [series_decompose_anomalies()](https://learn.microsoft.com/en-us/kusto/query/series-decompose-anomalies-function) (the built-in alternative: decomposes seasonality and trend, then applies a Tukey fence with default k = 1.5 to the residuals) · [make-series](https://learn.microsoft.com/en-us/kusto/query/make-series-operator) · [percentile(), percentiles()](https://learn.microsoft.com/en-us/kusto/query/percentiles-aggregation-function)
- CISA, NSA, FBI, ASD's ACSC and partners: [Identifying and Mitigating Living Off the Land Techniques](https://www.cisa.gov/sites/default/files/2025-03/Joint-Guidance-Identifying-and-Mitigating-LOTL508.pdf) (baselines, UEBA and ML-based anomaly detection)
- Sommer and Paxson: [Outside the Closed World: On Using Machine Learning for Network Intrusion Detection](https://www.umiacs.umd.edu/~tdumitra/courses/ENEE657/Fall19/papers/Sommer10.pdf) (IEEE S&P 2010)
- Arp et al.: [Dos and Don'ts of Machine Learning in Computer Security](https://www.usenix.org/system/files/sec22-arp.pdf) (USENIX Security 2022)
- MITRE ATT&CK: [T1213.002 Sharepoint](https://attack.mitre.org/techniques/T1213/002/) (including detection strategy DET0500) · [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) · MITRE ATLAS: [AML.T0020 Training Data Poisoning](https://atlas.mitre.org/techniques/AML.T0020)
- Microsoft Purview: [Audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities) (`FileDownloaded` vs `FileSyncDownloadedFull`)
- This log: [ANALYSIS.md, ML detection and the arithmetic of alert fatigue](../ANALYSIS.md#ml-detection-and-the-arithmetic-of-alert-fatigue) · [Day 05](2026-11-07-help-desk-social-engineering.md) (the help desk reset behind `r.patel`) · [Day 09](2026-11-11-deepfake-job-candidates-remote-worker-fraud.md) (a real account doing unusual things) · [Day 18](2026-11-20-data-poisoning-training-rag-memory.md) (poisoning, applied here to a baseline) · [Day 19](2026-11-21-logging-llm-apps-detect-abuse.md) (OAIC guidance) · October: [Day 07, parent–child anomalies](https://github.com/vipercipher/soc-lab-beginner/blob/main/learning-log/2026-10-17-office-parent-child-anomalies.md) and [Day 17, alert triage](https://github.com/vipercipher/soc-lab-beginner/blob/main/learning-log/2026-10-27-alert-triage.md)

⬅️ [Learning log index](README.md) · ➡️ [Day 21: AI-powered IDS: base rates, precision and drift (23 Nov)](2026-11-23-ai-ids-base-rates-precision-drift.md)
