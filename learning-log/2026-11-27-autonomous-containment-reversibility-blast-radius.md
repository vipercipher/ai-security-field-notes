# Day 25 — Autonomous Containment: Reversibility and Blast Radius

📅 27 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Days 22 to 24 were about a SOC AI that reads and writes: summaries,
queries, verdicts. A wrong summary costs an analyst some time. Today the
AI can act. It isolates laptops, disables accounts and blocks IP
addresses, and a wrong action costs someone else their working day, or
the whole company its payroll run.

Day 24 left a question hanging. One of LogInject's four attack goals was
false positive generation, which I read as getting the copilot to raise
alarms about nothing or recommend action against the wrong host. If it can
also isolate machines, the attacker no longer needs a foothold to hurt
you. Your own automation does it for them. ATT&CK lists cutting users
off from their accounts under Impact as
[T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531/):
"Adversaries may interrupt availability of system and network resources
by inhibiting access to accounts utilized by legitimate users." A
response agent that disables accounts on a weak signal can do that job
for them.

ANALYSIS.md's position is that "should the agent have containment
rights?" is the wrong question. Ask it per action, and score each one on
reversibility, blast radius and the cost of being wrong. Today puts that
into practice: what "reversible" actually means in a real product, how
to write the policy down, and how to check from the logs that the agent
stayed inside it.

---

## The concept

### Three questions per action

For every action an agent might take, ask:

| Question | What it really asks | Example |
|---|---|---|
| **How reversible is it?** | Who can undo it, how fast, and what's lost even after undo | Revoking sessions is undone the moment the user signs in again, but unsaved work is gone. A purged email can't be un-read by the attacker who already saw it |
| **How big is the blast radius?** | How many people and systems stop working if it's wrong | One laptop is one person. A payroll server is everyone's pay. An org-wide IP block can be every customer |
| **What happens if it's wrong, and if it's late?** | The cost of a false positive against the cost of waiting for a human | Ransomware moving laterally at 3 am doesn't wait for approval. A suspicious login to a mailbox usually can |

Reversibility is what makes speed affordable. If an action can be undone
in minutes by the SOC, you can accept more false positives in exchange
for acting fast. If it can't, you pay for the delay with a human
approval. That trade-off is the whole of today, and it's a judgement
call each organisation has to make for itself.

### "Reversible" is not the same as "free"

Microsoft's Defender documentation is a useful reality check, because it
lists the side effects of its own containment actions. These are all
from Microsoft Learn
([response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts),
[attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)):

| Action | It can be undone, but… |
|---|---|
| **Isolate device** | In environments that use web proxies, devices "might not be able to recover from network isolation", and Microsoft recommends selective isolation there. There's a downloadable script "for cases where isolated devices become unresponsive" |
| **Isolate an offline device** | Defender "retries enforcing the isolation for up to three days". An isolation the agent requested on Monday can land on Wednesday, when the laptop reconnects in the middle of a client meeting |
| **Contain device** | Containing a network device such as "a router that's acting as a default gateway" triggers a warning. Microsoft recommends "containing up to 100 devices at any given time" for performance |
| **Contain user** | When enforced on a domain controller, it "starts a GPO update on the Default Domain Controller policy", which syncs across domain controllers. Your change monitoring will see it |
| **Disable user** | For an account synced from Active Directory, it's disabled on the domain controllers and in Entra ID. Two places to re-enable, and anything running as that account stops in the meantime |

None of that is a reason not to contain. It's a reason to know, before
you automate an action, what "undo" really involves for your
environment.

### The best existing benchmark

ANALYSIS.md points to
[Microsoft's automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption)
as the pattern to study, and it's not an LLM. What the documentation says
it does:

- **A short list of actions.** Contain device, contain IP, isolate device,
  disable user, contain user, revoke sessions, suspend user and a few
  more. No open-ended "do whatever fixes it".
- **A stated confidence bar.** "For containment actions, Defender
  maintains a confidence level of 99% or higher based on real production
  data." That's Microsoft's own figure, measured as detector precision.
- **Audit mode first.** "Defender validates detectors in audit mode
  before broad release and gradually deploys only detectors that meet
  strict quality requirements."
- **Undo for everything.** "All automatic actions can be undone by your
  security team", through the Action center
  ([results and undo](https://learn.microsoft.com/en-us/defender-xdr/autoad-results)).
  Microsoft adds a caution: "Releasing a contained asset prematurely
  could allow an attacker to resume activity."
- **Exclusions for critical assets.** You can exclude users, device
  groups and IP ranges
  ([exclusions](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption-exclusions)),
  with Microsoft's own warning that excluding assets "isn't recommended"
  because it weakens protection.

That last pair is the trade-off in one product. The vendor would rather
you didn't exclude your servers, and the business would rather its
servers were never touched automatically. Both are right, which is why
someone at Northwind has to own the decision.

Day 21's arithmetic applies here too. A 99% precision detector is wrong
about 1 time in 100. At a few actions a month that's rare. If an LLM
agent is taking hundreds of actions, some will be wrong, so the question
becomes which ones, and how quickly they get undone.

### What the guidance says

| Source | What it says | What I take from it |
|---|---|---|
| [CISA, ASD's ACSC and partners, *Careful adoption of agentic AI services* (Apr 2026)](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services) | "Prevent agents from autonomously executing high impact actions or outputs without prior human approval". Also: "auditing and reversibility following task execution", "isolation and segmentation to limit blast radius", and "rate-limit components to interrupt long-running tasks and disrupt malicious workflows" | Co-authored by the Australian Signals Directorate. Human approval for high-impact actions is the baseline, not an extra |
| [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/) | Root causes are "excessive functionality; excessive permissions; excessive autonomy". Mitigations include "complete mediation", i.e. authorisation in downstream systems "rather than relying on an LLM to decide if an action is allowed", and rate-limiting as a damage limiter | The policy check belongs in code the model can't talk its way past |
| [NIST SP 800-61r3](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r3.pdf) (RS.MI-01) | Consider configuring technologies "to automatically perform some containment actions, like quarantining malware, transferring a compromised endpoint to an isolated remediation network". Also: "Allow incident handlers to manually select and perform containment actions instead of or in addition to automated containment measures" | Automated containment is normal. Keeping a human able to override it is required |

### Writing the policy down

ANALYSIS.md's autonomy table is the starting point. To make it
enforceable, each row needs numbers a machine can check. Here's
Northwind's version for four actions. The thresholds are my judgement,
a starting point to tune, not a standard:

| Action | Automatic? | Minimum independent signals | Never automatic on | Rate limit |
|---|---|---|---|---|
| Revoke sessions (one user) | Yes | 1 high-confidence detection | Break-glass accounts | — |
| Isolate device (one workstation) | Yes | 2 (e.g. the detection plus an EDR or identity signal) | Servers and anything on the critical asset list | Fewer than 3 per 15 minutes; beyond that, ask a human |
| Disable user | Yes, for standard users | 2 | Service accounts, admins, critical list | — |
| Block an IP organisation-wide | No, human approval | 2 | — | — |

Two design points from ANALYSIS.md carry the weight:

1. **The model recommends, code executes.** The agent calls a fixed
   `isolate_device(target, incident, signals)` function. That function
   checks the asset list, the signal count and the rate limit, and refuses
   if any fail. The model never holds a broad admin token. This is
   OWASP's complete mediation.
2. **Earn each level.** Each action moves through shadow (log what it
   would have done), recommend, approve, then automatic with rollback, on
   measured results, and drops back a level after a bad miss.

The rate limit is the control that answers Day 24. If an attacker can
make four laptops look compromised at once, a cap on automatic
isolations turns their denial of service into a page to the on-call
analyst.

---

## Sample logs

Everything is fictional. Northwind's SOC agent writes every action it
takes to **`NWSocAgentActions_CL`, a fictional custom table** (not a
Microsoft schema). Critical assets are kept in a Microsoft Sentinel
watchlist called `NWAssetTiers`; watchlists are a real Sentinel feature,
but the contents here are made up. Times in UTC; Northwind is on AEDT
(UTC+11), so the review window is Thursday 26 November in Sydney.

**NWAssetTiers watchlist** (3 rows)

```
SearchKey                          Tier       Owner
nw-pay01.northwind-example.com     Critical   Payroll
svc-backup@northwind-example.com   Critical   Infrastructure
nw-dc01.northwind-example.com      Critical   Infrastructure
```

**NWSocAgentActions_CL** (11 rows, fictional table)

```
TimeGenerated         ActionId  Incident  Action          Target                            DetectionRule                  Mode      ApprovedBy  Signals  Status     UndoneTime
2026-11-25T10:40:12Z  A-900     5498      IsolateDevice   nw-ws099.northwind-example.com    Ransomware note written        Auto      -           1        Completed  -
2026-11-25T21:14:05Z  A-901     5501      RevokeSessions  s.nguyen@northwind-example.com    Token replay from new country  Auto      -           1        Completed  -
2026-11-25T22:02:40Z  A-902     5502      IsolateDevice   nw-ws131.northwind-example.com    Credential dumping tool        Auto      -           2        Completed  -
2026-11-25T23:40:18Z  A-903     5503      IsolateDevice   nw-pay01.northwind-example.com    Suspicious service install     Auto      -           2        Undone     2026-11-26T00:05:51Z
2026-11-26T01:02:11Z  A-904     5504      IsolateDevice   nw-ws201.northwind-example.com    Office app spawned script      Auto      -           1        Undone     2026-11-26T02:31:09Z
2026-11-26T01:03:47Z  A-905     5504      IsolateDevice   nw-ws202.northwind-example.com    Office app spawned script      Auto      -           1        Undone     2026-11-26T02:31:15Z
2026-11-26T01:05:02Z  A-906     5504      IsolateDevice   nw-ws203.northwind-example.com    Office app spawned script      Auto      -           1        Undone     2026-11-26T02:31:22Z
2026-11-26T01:07:39Z  A-907     5504      IsolateDevice   nw-ws204.northwind-example.com    Office app spawned script      Auto      -           1        Undone     2026-11-26T02:31:30Z
2026-11-26T03:22:56Z  A-908     5505      BlockIPOrgWide  203.0.113.58                      C2 beacon pattern              Approved  k.ito       2        Completed  -
2026-11-26T04:15:33Z  A-909     5506      DisableUser     svc-backup@northwind-example.com  Unusual LDAP queries           Auto      -           2        Completed  -
2026-11-26T05:30:20Z  A-910     5507      DisableUser     t.brown@northwind-example.com     Password spray success         Auto      -           2        Completed  -
```

`Signals` is the number of independent signals the agent's action
function counted before acting. A-900 is from Wednesday evening in
Sydney (21:40 AEDT) and was covered by yesterday's review. The four
workstations in incident 5504 belong to Northwind's finance team; the
"script" turned out to be a month-end spreadsheet macro, and an analyst
released all four about an hour and a half later. The payroll server in
5503 was released after 25 minutes, once the "suspicious service" was
matched to a scheduled vendor update.

---

## What to look for

1. **Count the actions.** 11 rows, 10 of them on Thursday in Sydney. 9 of
   those 10 were automatic, and 1 (A-908) was approved by a human. 5 of
   the 10 were later undone, all of them device isolations.
2. **5503: corroboration doesn't shrink the blast radius.** The payroll
   server isolation had 2 signals, so it passed the signal check. It
   still shouldn't have been automatic, because `nw-pay01` is on the
   critical list. "Confident" and "safe to do without asking" are
   different questions.
3. **5504: four laptops in about five and a half minutes on one signal
   each.** The same detection rule fired four times and the agent
   isolated four finance machines between 01:02 and 01:07 UTC (12:02 to
   12:07 AEDT). Each one failed the two-signal minimum, and together they
   should have hit the rate limit. This is the pattern an attacker would
   use to turn your automation against you, and here it was a
   spreadsheet macro.
4. **5506: the wrong action nobody undid.** The agent disabled
   `svc-backup`, a service account on the critical list. Its status is
   still `Completed`. Undone actions show up in an overturn rate; a wrong
   action nobody noticed doesn't. It's the containment version of
   ANALYSIS.md's auto-closed true positive. Whatever runs as that account,
   tonight's backup job included, will fail until someone notices.
5. **What's inside the policy.** A-901 revoked one user's sessions on one
   high-confidence signal, which the policy allows. A-902 isolated one
   workstation with 2 signals. A-910 disabled a standard user with 2
   signals. A-908 is an org-wide block, which is never automatic, and k.ito
   approved it. None of these should be flagged.
6. **The overturn rate is the headline number.** The agent automatically
   isolated 6 devices on Thursday and 5 were released. That's an 83%
   overturn rate for automatic isolation in one day. One day is far too
   small a sample to judge on, but it's exactly the signal ANALYSIS.md
   says should demote an action back to "approve" while someone looks
   at why.

---

## Detection logic

**In plain English.**

- Look at the SOC agent's automatic actions for the previous day in
  Sydney time. Actions a human approved are out of scope for this rule.
- Flag an automatic action if any of these is true:
  - **Critical target:** the target is on the `NWAssetTiers` critical list.
  - **Not on the automatic list:** the action type should always need a
    human, or isn't in the policy at all.
  - **Too few signals:** fewer independent signals than the policy
    minimum for that action.
  - **Burst:** 3 or more automatic actions of the same type in the same
    15-minute window.
- Show how long each flagged action took to undo, or that it hasn't been.
- Separately, report the overturn rate per action type, which is what
  decides whether an action keeps its automatic status.

**KQL (Microsoft Sentinel).** `NWSocAgentActions_CL` is fictional, and
`NWAssetTiers` is a fictional watchlist read with the real
`_GetWatchlist()` function, which returns the watchlist with its
`SearchKey` column
([watchlist queries](https://learn.microsoft.com/en-us/azure/sentinel/watchlists-queries)).

```kql
// SOC agent automatic actions that broke Northwind's autonomy policy
let dayStart = datetime(2026-11-25T13:00:00Z);   // Thu 26 Nov 00:00 AEDT
let dayEnd   = datetime(2026-11-26T13:00:00Z);   // Fri 27 Nov 00:00 AEDT
let policy = datatable(Action:string, AutoAllowed:bool, MinSignals:int) [
    "RevokeSessions", true,  1,
    "IsolateDevice",  true,  2,
    "DisableUser",    true,  2,
    "BlockIPOrgWide", false, 2
];
let tiers = _GetWatchlist('NWAssetTiers')
    | project Target = tostring(SearchKey), Tier = tostring(Tier);
let autoActions = NWSocAgentActions_CL
    | where TimeGenerated >= dayStart and TimeGenerated < dayEnd
    | where Mode == "Auto"
    | extend Window = bin(TimeGenerated, 15m);
let bursts = autoActions
    | summarize BurstCount = count() by Action, Window
    | where BurstCount >= 3;
autoActions
| lookup kind=leftouter policy on Action
| lookup kind=leftouter tiers on Target
| lookup kind=leftouter bursts on Action, Window
| extend Tier = iff(isempty(Tier), "Standard", Tier)
| extend CriticalTarget = Tier == "Critical",
         NotAutoAllowed = isnull(AutoAllowed) or AutoAllowed == false,
         TooFewSignals  = isnotnull(MinSignals) and Signals < MinSignals,
         Burst          = isnotnull(BurstCount)
| where CriticalTarget or NotAutoAllowed or TooFewSignals or Burst
| extend MinutesToUndo = iff(Status == "Undone", bin((UndoneTime - TimeGenerated) / 1m, 1), real(null))
| order by Incident asc, ActionId asc
| project Incident, ActionId, Action, Target, Tier, Signals,
          CriticalTarget, NotAutoAllowed, TooFewSignals, Burst, BurstCount, Status, MinutesToUndo
```

And the overturn rate, over the same window:

```kql
NWSocAgentActions_CL
| where TimeGenerated >= datetime(2026-11-25T13:00:00Z) and TimeGenerated < datetime(2026-11-26T13:00:00Z)
| summarize Actions = count(), Undone = countif(Status == "Undone") by Action, Mode
| extend OverturnPct = round(100.0 * Undone / Actions, 0)
```

I ran the same logic in Python over the sample rows:

```
total 11 in window 10
bursts {('IsolateDevice', datetime.datetime(2026, 11, 26, 1, 0)): 4}
('5503', 'A-903', 'IsolateDevice', 'nw-pay01', 'Critical', 2, True, False, False, None, 'Undone', 25)
('5504', 'A-904', 'IsolateDevice', 'nw-ws201', 'Standard', 1, False, False, True, 4, 'Undone', 88)
('5504', 'A-905', 'IsolateDevice', 'nw-ws202', 'Standard', 1, False, False, True, 4, 'Undone', 87)
('5504', 'A-906', 'IsolateDevice', 'nw-ws203', 'Standard', 1, False, False, True, 4, 'Undone', 86)
('5504', 'A-907', 'IsolateDevice', 'nw-ws204', 'Standard', 1, False, False, True, 4, 'Undone', 83)
('5506', 'A-909', 'DisableUser', 'svc-backup@northwind-example', 'Critical', 2, True, False, False, None, 'Completed', None)
flagged 6 incidents ['5503', '5504', '5506']
not flagged ['A-901', 'A-902', 'A-908', 'A-910']
('RevokeSessions', 'Auto') 1 0 0
('IsolateDevice', 'Auto') 6 5 83
('BlockIPOrgWide', 'Approved') 1 0 0
('DisableUser', 'Auto') 2 0 0
```

**6 flagged actions across 3 incidents**: the payroll server (critical
target, undone after 25 minutes), the four finance laptops (too few
signals and a burst of 4, each undone after 83 to 88 minutes), and the
backup service account (critical target, never undone). The 4 actions
inside the policy are excluded, A-908 because a human approved it and
the rule only looks at automatic actions. A-900 would also break the
policy (1 signal for an isolation), but it falls outside Thursday's
window. The overturn query gives 83% for automatic isolation and 0% for
everything else.

`MinutesToUndo` uses `bin(..., 1)` on the elapsed minutes, which rounds
down, the same as the Python. A-904's real gap is 88 minutes 58 seconds.

**What I verified and what I didn't.** The Defender behaviour and quotes
come from the Microsoft Learn pages linked above, and the watchlist
function and `SearchKey` column from the Sentinel watchlist
documentation. The agent table, the watchlist contents and the policy
thresholds are fictional. I haven't run the query against a live
workspace.

**Tuning note:**

- **15-minute bins can split a burst.** Four actions at 01:13, 01:14,
  01:16 and 01:17 fall into two bins of two and wouldn't fire. A sliding
  window catches that but is more work in KQL. Better still, enforce the
  rate limit in the action function itself and use this query only to
  confirm it held.
- **The critical list is the control, so it has to be current.** A new
  payroll server that nobody added to `NWAssetTiers` is treated as a
  standard workstation. Review the list with asset owners, and consider
  treating any server OS as critical by default.
- **"Signals" has to mean independent.** Two alerts from the same EDR
  sensor about the same process are one signal counted twice. Define what
  counts in the action function, not in the agent's prompt, or the agent
  can argue itself past the minimum.
- **Overturn rate needs volume and a second number.** 5 of 6 is a
  striking day but a tiny sample. Track it weekly per action, and pair it
  with a sample of `Completed` actions that a human checks, because
  5506's disabled service account never shows up as overturned.
- **If you use Microsoft's attack disruption as well,** its actions are
  logged in the Action center. The `DisruptionAndResponseEvents` table
  shows their outcomes, such as blocked logons and policy updates, and
  "doesn't contain the execution of actions like contain user or disable
  user"
  ([table reference](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-disruptionandresponseevents-table)).
  Your own agent's actions need their own log, which is why this table
  exists.

**References:**
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
for the agent design, and
[ATT&CK T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531/)
for what a forced wrong action looks like from the attacker's side.

---

## Your turn

1. Score these four actions on reversibility, blast radius and cost of
   being wrong, then give each a starting autonomy level for Northwind:
   purge a reported phishing email from all mailboxes, reset a standard
   user's password, isolate a developer's laptop, block a SaaS app's
   OAuth consent organisation-wide.
2. Incident 5504 was a spreadsheet macro. Rewrite it as an attack: how
   could someone outside Northwind make four finance laptops look
   compromised at once? Then say which control in today's policy limits
   the damage, and what it costs on a day when the four laptops really
   are compromised.
3. The `svc-backup` disable was never undone. Design a check that would
   have caught it before the backup job failed, and say who should
   receive that alert.
4. Northwind's automatic isolation overturn rate was 83% on Thursday.
   Write the rule for demoting an action back to "approve": the
   threshold, the minimum sample size, who decides, and what has to
   happen before it's promoted again.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Automatic attack disruption in Microsoft Defender](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption) · [Exclude assets from automated responses](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption-exclusions) · [Details and results of an automatic attack disruption action](https://learn.microsoft.com/en-us/defender-xdr/autoad-results)
- Microsoft Learn: [Take response actions on a device in Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts) · [DisruptionAndResponseEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-disruptionandresponseevents-table) · [Build queries or rules with watchlists](https://learn.microsoft.com/en-us/azure/sentinel/watchlists-queries)
- CISA, ASD's ACSC and partners: [Careful adoption of agentic AI services](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services) ([PDF](https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFULADOPTIONOFAGENTICAISERVICES_FINAL.PDF))
- NIST: [SP 800-61r3, Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r3.pdf)
- OWASP: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- MITRE ATT&CK: [T1531 Account Access Removal](https://attack.mitre.org/techniques/T1531/)
- This log: [ANALYSIS.md, The line on autonomous containment](../ANALYSIS.md#the-line-on-autonomous-containment) · [Day 13](2026-11-15-threat-modelling-agents-trifecta-rule-of-two.md) (Rule of Two) · [Day 21](2026-11-23-ai-ids-base-rates-precision-drift.md) (base rates and precision) · [Day 24](2026-11-26-prompt-injection-through-logs.md) (attacking the SOC's AI)

⬅️ [Learning log index](README.md) · ➡️ Day 26: Guardrails for SOC agents: identity, rollback and kill switches (28 Nov)
