# Day 09 — Deepfake Job Candidates and Remote Worker Fraud

📅 11 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Days 01 to 08 were about someone pretending to be a person you already trust:
the CFO, a colleague, the help desk. Today the attacker doesn't borrow an
identity for one call. They get hired. They pass the interviews, receive a
laptop and an account, and from then on every login is "legitimate". No
password is stolen and no MFA is bypassed, because the account was issued to
them.

The best-documented version is North Korean remote IT workers. The FBI's
[October 2026 PSA](https://www.ic3.gov/PSA/2026/PSA261013) describes "thousands
of state-controlled remote 'IT Workers'" and says the North Korean government
receives an estimated 85–90% of the revenue they generate. It also lists stolen
data, extortion and, after termination, death threats against former managers.
This isn't only an American problem: the Australian Sanctions Office's
[advisory on cyber risks](https://www.dfat.gov.au/international-relations/security/sanctions/guidance/cyber-risks-dprk-it-workers-australian-businesses)
(6 November 2025) is aimed at Australian businesses. Citing CrowdStrike's 2024
threat hunting report (vendor research), it says high-paying countries such as
the US and Australia are specifically targeted. It also says further payments
after you suspect a DPRK worker "may be viewed as sanctions contraventions".

So a SOC analyst can end up in a meeting with HR and legal about a new starter
who has been at Northwind for nine days. Today is about what you can see from
your side.

---

## The concept

### Where AI fits, and where it doesn't

Same lesson as Day 01: the fake is an objection handler. It makes a stolen
identity look like the person on the call. It isn't the scheme.

| Stage | What the sources describe | Where AI shows up |
|---|---|---|
| **Build the persona** | Stolen or borrowed identities, matched to the target country, with email, social and GitHub accounts ([ASO](https://www.dfat.gov.au/international-relations/security/sanctions/guidance/cyber-risks-dprk-it-workers-australian-businesses)) | Microsoft says Jasper Sleet uses AI to generate name lists and email formats, and to pull required skills out of job ads so personas fit the role ([Microsoft, March 2026](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)) |
| **Pass the checks** | Valid but stolen identities clear background checks. The FBI says workers buy access to identity verification services to test stolen details first ([FBI, Oct 2026](https://www.ic3.gov/PSA/2026/PSA261013)) | Faceswap used to put workers' faces into stolen ID documents, sometimes the same AI-generated photo across several personas ([Microsoft, June 2025](https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/)) |
| **Pass the interview** | Video interviews, sometimes with a paid stand-in. The FBI says facilitators are paid to "appear on camera" and do interviews ([FBI, Oct 2026](https://www.ic3.gov/PSA/2026/PSA261013)) | The FBI reported AI and face-swapping during video interviews ([FBI, Jan 2025](https://www.ic3.gov/PSA/2025/PSA250123)). Microsoft reported voice changers to mask accents, and said in June 2025 it had *not yet* seen combined AI voice and video ([Microsoft, June 2025](https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/)) |
| **Get the laptop** | Shipped to a "laptop farm" run by a facilitator, who keeps it online from a home address and installs remote access software ([Microsoft](https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/), [FBI](https://www.ic3.gov/PSA/2026/PSA261013)) | — |
| **Do the job** | Real work, often subcontracted to cheaper freelancers. Remote desktop tools (AnyDesk, TeamViewer, RustDesk, Chrome Remote Desktop, Splashtop) or IP KVM hardware (TinyPilot, PiKVM) to drive the laptop ([FBI, Oct 2026](https://www.ic3.gov/PSA/2026/PSA261013)) | AI to write messages, answer technical questions and generate code ([Microsoft, March 2026](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)) |
| **Cash out** | Salary, plus copied code repositories, data theft and extortion ([FBI, Jan 2025](https://www.ic3.gov/PSA/2025/PSA250123)) | — |

ATT&CK maps the laptop-control step neatly:
[T1219.002 Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002/)
and [T1219.003 Remote Access Hardware](https://attack.mitre.org/techniques/T1219/003/),
which names IP KVM devices such as TinyPilot and PiKVM.

### The one public case to know: KnowBe4, July 2024

KnowBe4 (a security awareness vendor) published its own
[incident summary](https://blog.knowbe4.com/how-a-north-korean-fake-it-worker-tried-to-infiltrate-us).
Treat it as a vendor's account of its own incident, but it's unusually
specific:

| What they did | What happened |
|---|---|
| Four video interviews, photo matched to the application | Passed. The photo was an AI-"enhanced" stock image |
| Background check and references | Came back clear, because the identity was real and stolen |
| Shipped a Mac workstation | It started loading malware as soon as it arrived |
| EDR alert, 9:55 pm EST on 15 July | The SOC called the new hire, who blamed a router guide, said he was unavailable for a call and stopped responding |
| Containment | Around 10:20 pm EST, roughly 25 minutes later |

Two things I take from it. First, the controls that *failed* were the ones
that judge a person (interviews, photo matching, a background check on a stolen
identity). The control that *worked* was endpoint telemetry on the issued
device. Second, KnowBe4 says new employees started in a restricted area with no
production access, which limited the damage. That's a business-process control,
not a detection.

### What to change, and what it costs

The FBI's October 2026 PSA has the line that matters most: these workers
"cannot be identified reliably with a single indicator", so it recommends
"identity in depth", meaning several weak signals added up across the
employment lifecycle. It also warns that aggressive controls carry "unusually
high risks of generating false positives that could harm legitimate employees".

| Control | Source | The trade-off |
|---|---|---|
| **Live ID check, in person where possible** | FBI (Jan 2025): complete as much hiring and onboarding in person as possible. Microsoft: ID held up to the camera, recorded interviews | In-person is the strongest and the most expensive for remote roles. A video check is Day 03's problem again: you're judging media |
| **Ship the laptop only to the verified home address** | KnowBe4 and Microsoft both flag a different shipping address | Real people move house, stay with family and rent short-term. Treat a mismatch as a question to ask, not a verdict |
| **Block unsanctioned remote access tools** | Microsoft: WDAC or AppLocker, and hunt for unsanctioned RMM | Needs one sanctioned tool the help desk actually likes (Day 08) |
| **Least access for new starters** | KnowBe4's restricted start. ASO: review how much access remote workers have, especially payroll and personal information | Slows onboarding. Engineers complain in week one |
| **References by phone or video, not email** | KnowBe4 and Microsoft | More recruiter time per hire |
| **Cross-check applicants** | FBI: look for reused resume content, phone numbers (especially VoIP) and emails across applicants | Needs HR and security to share data, which is a privacy conversation in itself |

> 💡 **Judgement call:** I wouldn't try to detect the deepfake in the
> interview. Day 03 showed people and detectors both miss fakes, and in the
> KnowBe4 case four interviews didn't help. I'd put the effort into the
> laptop: where it ships, what runs on it, and where it connects from. That's
> data you already collect.

---

## Sample logs

All times are UTC (Sydney is UTC+11, so 22:10 UTC on 9 November is 09:10 on
10 November in Sydney). Everything is fictional. Tables are simplified.

**New starters** (**fictional custom table** `NorthwindNewStarters_CL`, 5 rows.
HR would own this. `ShipToState` is where IT sent the laptop):

```
Upn          Role          StartDate   WorkCountry  HomeState  ShipToState  DeviceName
a.lindqvist  Developer     2026-11-02  AU           QLD        VIC          DEV-ENG-31
c.reyes      Developer     2026-11-02  AU           NSW        NSW          DEV-ENG-32
d.osei       Data analyst  2026-11-02  AU           NSW        NSW          DEV-DA-07
j.whitford   Developer     2026-11-09  AU           WA         SA           DEV-ENG-33
t.mercer     IT support    2026-10-26  AU           NSW        NSW          DEV-IT-04
```

**Sign-ins** (inspired by Entra `SigninLogs`, 9 rows. `Location` is the
two-letter country code, `ResultType` 0 is success):

```
TimeGenerated     UserPrincipalName  IPAddress       Location  ResultType
2026-11-09 21:50  d.osei             192.0.2.140     NZ        0
2026-11-09 22:10  a.lindqvist        203.0.113.24    AU        0
2026-11-09 22:30  t.mercer           203.0.113.15    AU        0
2026-11-09 23:05  c.reyes            198.51.100.77   US        0
2026-11-10 00:05  j.whitford         203.0.113.90    AU        0
2026-11-10 00:20  d.osei             192.0.2.140     NZ        0
2026-11-10 01:40  a.lindqvist        203.0.113.24    AU        0
2026-11-10 02:30  c.reyes            198.51.100.77   US        0
2026-11-10 03:15  c.reyes            198.51.100.78   US        50126
```

**Process events** (inspired by `DeviceProcessEvents`, 5 rows. `AccountUpn`
shortened to the user name):

```
Timestamp         AccountUpn   DeviceName  FileName
2026-11-09 20:15  k.brandt     DEV-FIN-02  teamviewer.exe
2026-11-09 23:20  c.reyes      DEV-ENG-32  anydesk.exe
2026-11-10 00:40  t.mercer     DEV-IT-04   quickassist.exe
2026-11-10 01:52  a.lindqvist  DEV-ENG-31  rustdesk.exe
2026-11-10 02:05  j.whitford   DEV-ENG-33  code.exe
```

Context (fictional): Northwind's sanctioned remote support tool is Quick Assist
(Day 08), and `t.mercer` works on the help desk. `d.osei` is in Auckland this
week for a family wedding, approved by their manager. `j.whitford` asked for
the laptop to go to a parent's address in Adelaide while moving house.
`k.brandt` has been in finance for six years.

---

## What to look for

1. **Count first.** **5** new starters, **9** sign-ins (**8** successful,
   **1** failure with `ResultType` 50126), **5** process events, of which
   **3** are third-party remote desktop tools (`teamviewer.exe`,
   `anydesk.exe`, `rustdesk.exe`).
2. **`c.reyes`: the direct route.** A Sydney-based developer with **2**
   successful sign-ins from the US (23:05 and 02:30 UTC, which is 10:05 and
   13:30 in Sydney, during their working day) plus a failed one, and AnyDesk
   on their laptop at 23:20, 15 minutes after the first foreign sign-in. Either
   alone has an innocent explanation. Together, on a nine-day-old account,
   they don't.
3. **`a.lindqvist`: the laptop-farm route.** Every sign-in is from Australia,
   so a geography rule sees nothing. That's the point of a laptop farm: the
   device sits in-country and the person drives it from somewhere else. What
   shows is the laptop shipped to Victoria for someone who lives in Queensland,
   and RustDesk running on it at 01:52 UTC.
4. **The decoys.** `d.osei` signs in from New Zealand, which is a foreign
   location, but nothing else is odd and there's a known reason. `j.whitford`
   has a shipping mismatch and nothing else. `t.mercer` runs a remote tool,
   but it's the sanctioned one. A single-signal rule would flag all three.
5. **Out of scope, not ignored.** `k.brandt` running TeamViewer is an
   unsanctioned tool on a finance laptop. It isn't a fake-worker signal (six
   years of tenure), but it belongs in your normal unsanctioned-software
   process.

---

## Detection logic

**In plain English:** for anyone who started in the last **30 days**, score
three signals: successful sign-ins from a country other than their work
country, an unsanctioned remote desktop tool on any device they used, and a
laptop shipped to a different state from their home address. Alert when the
score is **2 or more**. This follows the FBI's "identity in depth" idea: no
single signal is trusted on its own.

**KQL (Microsoft Sentinel / Defender XDR advanced hunting, with a fictional
custom table):**

```kql
// New starters with two or more remote-worker fraud signals
// NorthwindNewStarters_CL is a FICTIONAL custom table owned by HR (see text)
let lookback = 30d;
let unsanctionedRemote = dynamic(["anydesk.exe", "teamviewer.exe", "rustdesk.exe"]);
let starters =
    NorthwindNewStarters_CL
    | where StartDate > ago(lookback)
    | project Upn = tolower(Upn), WorkCountry, DeviceName,
              ShipSignal = iff(HomeState != ShipToState, 1, 0);
let geo =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "0"
    | extend Upn = tolower(UserPrincipalName)
    | join kind=inner (starters | project Upn, WorkCountry) on Upn
    | where Location != WorkCountry
    | summarize ForeignSignins = count(), Countries = make_set(Location) by Upn;
let remote =
    DeviceProcessEvents
    | where Timestamp > ago(lookback)
    | where FileName in~ (unsanctionedRemote)
    | extend Upn = tolower(AccountUpn)
    | summarize RemoteTools = make_set(tolower(FileName)) by Upn;
starters
| join kind=leftouter geo on Upn
| join kind=leftouter remote on Upn
| extend GeoSignal = iff(coalesce(ForeignSignins, 0) > 0, 1, 0),
         RemoteSignal = iff(coalesce(array_length(RemoteTools), 0) > 0, 1, 0)
| extend Score = GeoSignal + RemoteSignal + ShipSignal
| where Score >= 2
| project Upn, DeviceName, Score, GeoSignal, Countries,
          RemoteSignal, RemoteTools, ShipSignal
```

On the sample it returns **2 rows**. I ran the same logic in Python over the
rows above to check:

```
starters 5 signins 9 procs 5
FIRE a.lindqvist score 2 foreign 0 [] tools ['rustdesk.exe'] ship True
FIRE c.reyes score 2 foreign 2 ['US'] tools ['anydesk.exe'] ship False
     d.osei score 1 foreign 2 ['NZ'] tools [] ship False
     j.whitford score 1 foreign 0 [] tools [] ship True
     t.mercer score 0 foreign 0 [] tools [] ship False
out of scope rmm: [('2026-11-09 20:15', 'k.brandt', 'DEV-FIN-02', 'teamviewer.exe')]
```

What it excludes: `d.osei` and `j.whitford` score 1 each, `t.mercer` scores 0
because `quickassist.exe` isn't on the list, and `k.brandt` isn't a new starter
so never enters the query. The failed `c.reyes` sign-in at 03:15 is dropped by
`ResultType == "0"`, so `ForeignSignins` is 2, not 3.

**What I verified and what I didn't.** `SigninLogs` columns
(`UserPrincipalName`, `IPAddress`, `Location`, `ResultType`, `TimeGenerated`)
are from Microsoft's current table reference, which describes `Location` as the
two-letter country code and `ResultType` 0 as success. `DeviceProcessEvents`
columns are as in Day 08. The HR table is invented, and in a real workspace
its column names depend on how you ingest it. The three process names are a
starting list I haven't checked against every version of each product, so I
match case-insensitively (`in~`). Microsoft's Jasper Sleet post points to a
GitHub repository of RMM hunting queries (`RemoteManagementMonitoringTools`). Build your list from that and from what actually
shows up on your devices. And this query can't see an IP KVM device at all:
there's no process to find. That needs a USB or peripheral inventory.

**Tuning note:** the 30-day window, the threshold of 2 and equal weighting are
my starting points, not published figures. Expect false positives from
contractors who bring their own tools, staff travelling, and anyone on a
consumer VPN (which also makes `Location` unreliable in both directions). Keep
the signal set wide and the threshold at 2 rather than raising it: an attacker
who learns your rule can drop one signal more easily than two. When it fires,
this is **not** a SOC-only call. The FBI warns about harming legitimate
employees, and the ASO says to suspend payments and contact them if you
suspect a DPRK worker. Bring in HR and legal, limit the account's access while
identity is re-verified in person or through a trusted process (Day 05), and
check what the account touched: code repositories, shared drives, and any new
authentication methods (Day 07).

---

## Your turn

1. In the KnowBe4 case, which controls failed and which one worked? Sort them
   into "judges the person" and "watches the device", and say what that
   suggests about where to spend effort.
2. `a.lindqvist` has no foreign sign-ins at all. Explain why, using the
   laptop-farm description, and name one signal *not* in today's query that
   might catch an IP KVM device.
3. Write the conversation plan for `c.reyes`'s manager: who should be in the
   room, what you'd ask, and what you would *not* do before identity is
   re-checked. Keep in mind the FBI's warning about false positives.
4. Pick one onboarding change from the table for Northwind. Describe the cost
   to a legitimate remote hire, and how you'd keep it from becoming an
   unofficial "ban list" based on names or nationalities.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- FBI: [North Korean IT Workers Expanding Use of Facilitators, Broadening Recruitment (I-101326-PSA, Oct 2026)](https://www.ic3.gov/PSA/2026/PSA261013) · [North Korean IT Workers Conducting Data Extortion (I-012325-PSA, Jan 2025)](https://www.ic3.gov/PSA/2025/PSA250123)
- Australian Sanctions Office: [Cyber risks of DPRK IT workers to Australian businesses](https://www.dfat.gov.au/international-relations/security/sanctions/guidance/cyber-risks-dprk-it-workers-australian-businesses)
- Microsoft Threat Intelligence: [Jasper Sleet: North Korean remote IT workers' evolving tactics to infiltrate organizations](https://www.microsoft.com/en-us/security/blog/2025/06/30/jasper-sleet-north-korean-remote-it-workers-evolving-tactics-to-infiltrate-organizations/) · [AI as tradecraft: How threat actors operationalize AI](https://www.microsoft.com/en-us/security/blog/2026/03/06/ai-as-tradecraft-how-threat-actors-operationalize-ai/)
- KnowBe4 (vendor's own incident summary): [How a North Korean Fake IT Worker Tried to Infiltrate Us](https://blog.knowbe4.com/how-a-north-korean-fake-it-worker-tried-to-infiltrate-us)
- Microsoft Learn: [SigninLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs) · [DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- MITRE ATT&CK: [T1219.002 Remote Desktop Software](https://attack.mitre.org/techniques/T1219/002/) · [T1219.003 Remote Access Hardware](https://attack.mitre.org/techniques/T1219/003/)
- This log: [Day 01](2026-11-03-deepfake-bec-anatomy.md) (the fake as objection handler) · [Day 03](2026-11-05-why-people-and-detectors-miss-fakes.md) (why spotting fakes fails) · [Day 08](2026-11-10-teams-vishing-external-tenants-remote-access.md) (remote access tools)

⬅️ [Learning log index](README.md) · ➡️ [Day 10: How LLM apps fail: the OWASP LLM Top 10 (12 Nov)](2026-11-12-owasp-llm-top-10.md)
