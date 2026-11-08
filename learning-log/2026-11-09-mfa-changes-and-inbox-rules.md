# Day 07 — After the Reset: Detecting MFA Changes and Inbox Rules

📅 9 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Days 05 and 06 were about the front door: how a help desk gets talked into a
reset, and what the account accepts once it has been reset. Today is the first
ten minutes *after* that goes wrong. The attacker is in, and the account is
about to be made theirs.

Two things tend to happen quickly, and both leave audit records. The attacker
changes the **authentication methods**, so they can get back in after the real
owner is locked out or resets the password. Then they set up the **mailbox**, so
the owner doesn't see replies and the attacker can see everything. MITRE
describes both. [T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/)
covers enrolling a new device or method to bypass MFA and keep access, and
[T1114.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
notes that forwarding rules can keep giving access to someone's mail even after
credentials are reset.

This is also where Day 01's chain picks up. A payment-fraud attacker who sits
inside the finance mailbox doesn't need a deepfake at all. They can read the
real thread and answer it.

---

## The concept

### Two kinds of persistence

| What they change | Why | Where it's logged | ATT&CK |
|---|---|---|---|
| **Sign-in methods** (add an Authenticator app, add a phone, remove the owner's old method) | Get back in later, and push the real owner out | Entra `AuditLogs` | [T1098.005](https://attack.mitre.org/techniques/T1098/005/) |
| **Inbox rules** (delete, move, mark as read) | Hide replies, bank-detail warnings and security alerts from the owner | Exchange audit, via `OfficeActivity` or `CloudAppEvents` | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) |
| **Mailbox forwarding** | Get a copy of everything, outside the account | Same | [T1114.003](https://attack.mitre.org/techniques/T1114/003/) |

### What the Entra audit log calls it

Microsoft's audit activity reference (read on 9 November 2026) lists these
`UserManagement` activities for security info, and these are the strings you
filter on:

- `User registered security info` and `Admin registered security info`
- `User deleted security info` and `Admin deleted security info`
- `User updated security info` and `Admin updated security info`

The `AuditLogs` table in Log Analytics has the columns `OperationName`,
`Category`, `Result` (`success`, `failure`, `timeout`, `unknownFutureValue`),
`InitiatedBy`, `TargetResources`, `LoggedByService` and `TimeGenerated`. One
thing I did **not** confirm is exactly which activity a Temporary Access Pass
issue produces. Look at your own tenant's log the next time one is issued,
rather than assuming it appears under these names.

### What a malicious inbox rule looks like

Microsoft's [alert classification playbook for inbox manipulation rules](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules)
says attackers set rules to delete mail, move it to a less noticeable folder
(its example is the **RSS** folder), or forward it to an external account. Its
investigation steps point at these things:

| Rule feature | What the playbook says | My reading |
|---|---|---|
| Keywords in `BodyContainsWords`, `SubjectContainsWords` or `SubjectOrBodyContainsWords` | Common scenarios filter on words like "phish", "spam", "do not reply" | In a BEC case I'd also expect "invoice", "payment" and "bank details". That's my judgement, not the playbook's wording |
| `MoveToFolder` to an obscure folder, with `MarkAsRead` | Destination folder related to the keywords is worth a look | The pairing is stronger than either alone |
| Delete every incoming email, no filter | Called out as suspicious | Rare in legitimate use |
| Operations | `New-InboxRule`, `Set-InboxRule`, `UpdateInboxRules` (its sample query also includes `Set-Mailbox`) | `Set-Mailbox` is how a mailbox-wide forward shows up |

The playbook also says to look at the IP address and at what the user did
before creating the rule, which is exactly today's detection: the rule on its
own is weak, the rule shortly after a method change is strong.

Vendor research, to show it isn't theoretical: Expel's
[seven ways to spot BEC in Microsoft 365](https://expel.com/blog/seven-ways-to-spot-business-email-compromise-microsoft-365/)
describes an investigation where an attacker created a rule that moved mail
containing "WeTransfer" into the "RSS subscriptions" folder, and shows the
audit record with parameters such as `MoveToFolder`, `MarkAsRead` and
`StopProcessingRules`. It's one vendor's casework, not a statistic.

### The trade-off nobody likes

Inbox rules are a normal feature, and people do move newsletters into the RSS
folder. A rule that fires on "any rule to a hidden folder" will be wrong all day
and ignored by Friday. The signal comes from **context**: who, when, from where,
and what else happened to the account in the last two hours.

> 💡 **Judgement call:** I'd rather have a narrow rule that nearly always means
> something than a broad one I have to switch off. The cost is that an attacker
> who skips `MarkAsRead` slips past today's rule. I'd accept that for an alert
> and cover it with a weekly review of rules created by users who changed their
> methods.

---

## Sample logs

All times are UTC on **Friday 6 November 2026** (Sydney is UTC+11). Everything
is fictional, and the IPs are documentation ranges. This continues Day 06:
`f.cole` lost a phone and the help desk issued a Temporary Access Pass, and the
TAP sign-in to Northwind Payments was logged at **02:30 from 192.0.2.44**. Both
tables below are **simplified, flattened extracts**, not the raw schema. In the
real tables the details sit in dynamic columns (`InitiatedBy`, `TargetResources`,
`Parameters`).

**Entra audit log** (inspired by `AuditLogs`, 5 rows, all `success`):

```
Time      User     OperationName                  Detail                                  IP
00:50:14  a.chen   User registered security info  FIDO2 security key                      203.0.113.10
02:09:41  e.ito    User registered security info  Microsoft Authenticator                 198.51.100.23
02:33:07  f.cole   User registered security info  Microsoft Authenticator                 192.0.2.44
02:36:52  f.cole   User deleted security info     Microsoft Authenticator (old device)    192.0.2.44
03:10:25  d.ward   User registered security info  FIDO2 security key                     198.51.100.7
```

**Exchange audit** (inspired by `OfficeActivity`, workload `Exchange`, 5 rows;
`Parameters` flattened to key=value):

```
Time      User     Operation       Parameters                                                                                                            IP
01:20:33  a.chen   New-InboxRule   Name=Digests; SubjectContainsWords=weekly digest; MoveToFolder=RSS Subscriptions; MarkAsRead=False                     203.0.113.10
01:50:09  b.diaz   New-InboxRule   Name=Newsletters; SubjectContainsWords=newsletter; MoveToFolder=Newsletters                                           203.0.113.11
02:41:18  f.cole   New-InboxRule   Name=.; SubjectOrBodyContainsWords=invoice;payment;bank details; MoveToFolder=RSS Subscriptions; MarkAsRead=True; StopProcessingRules=True   192.0.2.44
02:44:03  f.cole   Set-Mailbox     ForwardingSmtpAddress=smtp:collect@mail-relay.example                                                                 192.0.2.44
03:55:40  j.khan   New-InboxRule   Name=Receipts; SubjectContainsWords=receipt; MoveToFolder=Receipts                                                    203.0.113.15
```

Context (fictional): `a.chen` enrolled a security key at their desk. `d.ward`
was finishing the rollout from Day 06. `e.ito` is the odd-IP weak sign-in from
Day 06, and nobody has spoken to them yet. `f.cole` is on leave and says they
were not at a computer.

---

## What to look for

1. **Count first.** **5** audit rows and **5** Exchange rows. Of the audit rows,
   **4** are registrations and **1** is a deletion.
2. **The sequence for `f.cole`.** TAP sign-in at 02:30:00, a new Authenticator
   method **3 min 7 s** later, the old device's method deleted **3 min 45 s**
   after that, an inbox rule at 02:41:18 (**8 min 11 s** after the first change)
   and a mailbox forward **2 min 45 s** after the rule. Five steps in 14
   minutes, all from `192.0.2.44`. Enrolling in a new method is what a
   legitimate recovery looks like too. It's the rule and the forward that turn
   it.
3. **Deleting the old method matters.** Adding a method keeps the attacker in.
   Removing the owner's method keeps the owner *out*. Treat the pair as a
   stronger signal than either alone.
4. **The rule's content.** `Name=.` is a deliberately meaningless name. The
   keywords are payment words, the destination is the RSS folder, `MarkAsRead` is
   `True` and `StopProcessingRules` is `True`. The forward goes to a domain
   Northwind doesn't own.
5. **The decoy that must not fire.** `a.chen` registered a key at 00:50:14 and
   created an RSS rule **30 min 19 s** later from the same corporate IP.
   Judged on folder and timing alone, that's a hit. The difference is
   `MarkAsRead=False`, a weekly-digest keyword and a known IP. That is why the
   rule below doesn't treat "RSS folder" as enough by itself.
6. **Rules with no method change.** `b.diaz` and `j.khan` created ordinary
   folder rules and neither changed a method. Both are noise.
7. **A method change with no rule.** `e.ito` registered Authenticator from the
   unfamiliar IP from Day 06, with no rule or forward afterwards. This is **not**
   an alert under today's logic, but it shouldn't be left alone: someone should
   check with `e.ito` today. Not every real problem is an alert.

---

## Detection logic

**In plain English:** find users who changed their sign-in methods and, within
the next **2 hours**, created a *sensitive* Exchange rule or forward. A
sensitive rule deletes mail, forwards or redirects it, or moves it to a hidden
folder **and** marks it as read. Report one row per user.

**KQL (Microsoft Sentinel / Log Analytics, `AuditLogs` and `OfficeActivity`):**

```kql
// Sign-in method change followed by a sensitive mailbox rule or forward
let window = 2h;
let hiddenFolders = dynamic(["RSS Subscriptions", "RSS Feeds", "Junk Email",
                             "Deleted Items", "Conversation History"]);
let methodChanges =
    AuditLogs
    | where TimeGenerated > ago(1d)
    | where Result == "success"
    | where OperationName in ("User registered security info",
                              "User deleted security info",
                              "User updated security info",
                              "Admin registered security info",
                              "Admin deleted security info",
                              "Admin updated security info")
    | extend Upn = tolower(tostring(iff(OperationName startswith "Admin",
                 TargetResources[0].userPrincipalName,
                 InitiatedBy.user.userPrincipalName)))
    | project ChangeTime = TimeGenerated, Upn, ChangeOp = OperationName;
OfficeActivity
| where TimeGenerated > ago(1d)
| where OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| mv-apply p = parse_json(Parameters) on (
    summarize Cfg = make_bag(bag_pack(tostring(p.Name), tostring(p.Value))))
| extend Forwards = isnotempty(tostring(Cfg.ForwardTo))
                 or isnotempty(tostring(Cfg.ForwardAsAttachmentTo))
                 or isnotempty(tostring(Cfg.RedirectTo))
                 or isnotempty(tostring(Cfg.ForwardingSmtpAddress))
                 or isnotempty(tostring(Cfg.ForwardingAddress)),
         Deletes  = tostring(Cfg.DeleteMessage) == "True",
         Hides    = tostring(Cfg.MoveToFolder) in (hiddenFolders)
                    and tostring(Cfg.MarkAsRead) == "True"
| where Forwards or Deletes or Hides
| extend Upn = tolower(UserId), RuleTime = TimeGenerated
| join kind=inner methodChanges on Upn
| where RuleTime between (ChangeTime .. (ChangeTime + window))
| summarize FirstChange = min(ChangeTime), ChangeOps = make_set(ChangeOp),
            RuleEvents = dcount(RuleTime), Ops = make_set(Operation),
            IPs = make_set(ClientIP) by Upn
```

On the sample it returns **1 user** (`f.cole`), with **2** sensitive Exchange
events (the rule and the forward) and **2** method changes (a registration and
a deletion). I ran the same logic in Python over the rows above to check:

```
Upn     FirstChange  ChangeOps                                   RuleEvents  Ops
f.cole  02:33:07     registered + deleted security info          2           New-InboxRule, Set-Mailbox
```

The other three Exchange events drop out for different reasons. `b.diaz` and
`j.khan` created folder rules that don't hide or forward anything. `a.chen`'s
rule was within two hours of a registration but goes to the RSS folder **without**
marking it read, so it fails the `Hides` test. Without the `MarkAsRead` test, the
folder-only version of this rule would have flagged `a.chen` as well
(**3** sensitive-looking events instead of **2**).

The field names are the ones in Microsoft's table references: `AuditLogs`
(`OperationName`, `Result`, `InitiatedBy`, `TargetResources`, `TimeGenerated`)
and `OfficeActivity` (`Operation`, `OfficeWorkload`, `UserId`, `ClientIP`,
`Parameters`, `TimeGenerated`). The **`Parameters` handling is the fragile
part**. I've assumed the Name/Value array that Expel's sample shows. Rules made
through Outlook or OWA can be logged as `UpdateInboxRules` with a different
structure, and this query doesn't cover them. Print a few real events from your
own tenant before trusting it. Microsoft's own playbook queries `CloudAppEvents`
instead, which is the better table if you're on Defender XDR.

**Tuning note:** the 2-hour window and the folder list are my starting points.
Widen the window if your attackers are patient and your help desk is slow to
notice. Excluding by IP is tempting, but a VPN or residential proxy defeats it,
so I'd use IP as extra triage context, not as a filter. The main false positive
is a real person who re-enrols a phone and tidies their inbox on the same
afternoon, which is why the sensitivity test on the rule matters. Admin-driven
changes (help desk) will show up as `Admin ...` rows against the target user.
Expect them during recovery, and treat a sensitive rule after a help desk reset
as the one to look at first. When it fires: disable the rule and forward, review
the sign-in IP, revoke sessions and review the methods before resetting
anything, so the attacker can't re-enrol while you work.

---

## Your turn

1. In your own words, why is *deleting* a sign-in method a stronger signal
   than adding one? Use the phrase "locked out" in your answer.
2. Rebuild `f.cole`'s timeline from 02:30:00 to 02:44:03, with the Sydney times
   in brackets and the ATT&CK technique for each step.
3. Today's rule requires `MarkAsRead=True` on a hidden-folder move. Describe
   how an attacker might avoid the rule, and what second control you'd rely on.
   Don't write anything that works against a real tenant.
4. `e.ito` changed a method from an unfamiliar IP and nothing else. Write the
   three checks you'd make today, and decide whether this should page someone.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Alert classification for suspicious inbox manipulation rules](https://learn.microsoft.com/en-us/defender-xdr/alert-grading-playbook-inbox-manipulation-rules)
- Microsoft Learn: [Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- Microsoft Learn: [AuditLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/auditlogs) · [OfficeActivity table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/officeactivity)
- MITRE ATT&CK: [T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/) · [T1114.003 Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003/)
- Vendor research: [Expel, seven ways to spot BEC in Microsoft 365](https://expel.com/blog/seven-ways-to-spot-business-email-compromise-microsoft-365/)
- This log: [Day 05](2026-11-07-help-desk-social-engineering.md) (the reset) · [Day 06](2026-11-08-phishing-resistant-mfa-recovery-path.md) (the recovery path and `f.cole`'s TAP)

⬅️ [Learning log index](README.md) · ➡️ Day 08: Vishing over Teams: external tenants and remote access tools (10 Nov)
