# Day 05 — Help Desk Social Engineering and Verifying a Caller

📅 7 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Day 04 protected the payment. Today is the other soft spot that ANALYSIS.md
flags: the **help desk**. If a caller can get a password reset and a new MFA
device from a person on the phone, it doesn't matter how good your MFA is. The
attacker never touches it. They just ask for it to be replaced.

A voice clone (Day 02) helps here but isn't needed. The CISA and FBI
[Scattered Spider advisory](https://www.ic3.gov/CSA/2025/250729.pdf) (first
published November 2023, updated 29 July 2025) describes actors who pose as employees
to convince help desk staff to reset the employee's password and
transfer the employee's MFA to a device they control. It says these
attempts first learn what steps a help desk needs for a reset, and
that the social engineering frequently happens over several calls. That detail
shapes the detection below: the first call may not ask for anything.

---

## The concept

### The help desk is built to be helpful

A help desk is measured on speed and satisfaction, and its job is to get locked-out
people working again. A caller who is stressed, in a hurry and "travelling for the
board" is exactly the person it's designed to help. Attackers don't beat
the process so much as use its purpose. That's a design problem more than a
training problem, and telling agents to "be vigilant" won't fix it.

### Which checks prove nothing?

| Check | Why it's weak | Judgement |
|---|---|---|
| **Knowledge questions** (employee ID, date of birth, manager's name) | Information that leaks, is on a profile, or sits in an earlier breach. The advisory notes actors gather personal details before calling | Fine as a *triage* step, not as proof |
| **Caller ID matches the directory** | Caller ID can be spoofed, and a SIM swap (also in the advisory) moves the real number to the attacker | A clue, never a verification |
| **"I'm in the office, can't you see me?"** | Anything that depends on the agent's gut feeling | Remove from the process |
| **A voice that sounds right** | Day 02 and Day 03: people are poor at this, and clones are improving | Not evidence either way |
| **Urgency or seniority** | The pressure *is* the attack | Treat as a reason to slow down |

### Which checks do real work?

The aim is **proof that the caller controls something only the employee should**,
or a confirmation that comes through a channel the attacker doesn't control.

| Option | How it works | Trade-off |
|---|---|---|
| **Directory call-back** | The agent hangs up and calls the number in the HR/directory record | Needs a trusted number. If the attacker has already changed the directory entry, or the employee is abroad on a new SIM, it breaks down |
| **Manager confirmation** | The agent phones the manager on a directory number | Managers are also phishing targets and may be on leave. Often slow |
| **Verified ID with Face Check** | Microsoft's [verified help desk pattern](https://learn.microsoft.com/en-us/entra/verified-id/helpdesk-with-verified-id) has the caller present a `VerifiedEmployee` credential with Face Check, wired into the service desk tool, which can then trigger actions such as issuing a Temporary Access Pass | Requires setup, credential issuance to every employee, and a service desk with API support. It is a Microsoft design pattern, not a guarantee |
| **Existing strong credential** | Caller proves identity with a passkey or security key they still hold | Doesn't help in the main case: they're calling *because* they've lost it |

> 💡 **Judgement call:** I would rather a help desk be slow and consistent than fast
> and clever. The best process takes the decision away from the agent: the tool
> shows green or red, and the agent can't turn red into green by feeling sure.

### What you give the caller matters as much as how you verify them

Once verified, don't read a new password over the phone. Microsoft's
[Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
is a time-limited passcode (lifetime from 10 minutes to 30 days, with a one-time-use
option) that lets a user sign in and register a passkey or authenticator. That is
a better bootstrap than a password, but you should keep it short and one-time. It
also becomes the thing an attacker wants, so an "issued TAP" event should itself
be watched (that's Day 07).

### The cost of saying no

Declining a real executive's reset has a price. They're locked out, annoyed and
possibly mid-deal. Agents need cover: a documented rule that applies to everyone,
a way to escalate that doesn't blame the agent, and leadership that has said in
advance that the rule applies to them too. Without that, the process lasts until
the first senior person complains.

---

## Sample logs

All times are UTC on **Friday 6 November 2026** (Sydney is UTC+11). All data is
fictional. `NorthwindHelpdesk_CL` is a **fictional custom table**: no real service
desk product logs exactly these columns, though most store the same facts.
Phone numbers are shortened to the last four digits of a fictional
(02) 5550 number range, which is set aside for fiction in Australia. `NumberInDirectory`
says whether the caller's number matches a number on the employee's directory record.
`VerificationMethod` is what the agent *recorded*, which is a claim (Day 04).

```
TicketId  Time   Agent  Employee   CallerNumber  NumberInDirectory  RequestType        VerificationMethod  Outcome
HD-8801   00:12  mei    dana.lee   ..0141        N                  ProcedureQuestion  None                Completed
HD-8802   00:41  tom    dana.lee   ..0141        N                  ProcedureQuestion  None                Completed
HD-8803   01:20  mei    r.okafor   ..0155        Y                  PasswordReset      DirectoryCallback   Completed
HD-8804   02:05  tom    dana.lee   ..0141        N                  MfaReset           KnowledgeQuestions  Completed
HD-8805   02:40  noor   j.nguyen   ..0162        Y                  PasswordReset      VerifiedID          Completed
HD-8806   03:15  mei    p.shah     ..0170        N                  PasswordReset      KnowledgeQuestions  Completed
HD-8807   04:30  noor   l.martin   ..0188        Y                  MfaReset           CallerIdMatch       Completed
HD-8808   05:10  tom    k.brown    ..0192        Y                  PasswordReset      DirectoryCallback   Completed
HD-8809   05:55  mei    s.adams    ..0201        N                  PasswordReset      KnowledgeQuestions  Declined
HD-8810   06:30  noor   t.wong     ..0215        Y                  MfaReset           VerifiedID          Completed
```

What was found out later (fictional): the caller on `..0141` was not Dana Lee. The
two early calls asked how a reset works at Northwind and what the agent needs
to hear. The third call, an MFA reset, used answers taken from a public profile.
Priya Shah (HD-8806) really was travelling and had lost her phone. Nothing was
wrong with her request, although the process behind it was no stronger than
Dana's.

---

## What to look for

1. **The probing calls.** HD-8801 and HD-8802 come from the same number about the
   same employee, ask no one to change anything, and get answers. These match the
   advisory's description of learning the procedure first. Nothing here would alert
   on its own, and individually they look like harmless questions.
2. **The reset that follows.** HD-8804 is an **MfaReset** from the same number
   84 minutes after the second probe (00:41 to 02:05), verified only with
   `KnowledgeQuestions`. This is the dangerous one.
3. **A weak method on a legitimate request.** HD-8806 (p.shah) used
   `KnowledgeQuestions` for a **PasswordReset** and was a real employee. The log
   alone can't tell a legitimate traveller from an attacker, which is the point:
   the control failed even though the outcome was fine.
4. **Caller ID treated as verification.** HD-8807 records `CallerIdMatch` for an
   **MfaReset**. The number was in the directory (`Y`) and that's the only
   reason it looks safe.
5. **The control that worked.** HD-8809 used `KnowledgeQuestions` but was
   **Declined**. HD-8803, HD-8805, HD-8808 and HD-8810 all used a strong
   method (`DirectoryCallback` or `VerifiedID`).
6. **Counts.** 10 tickets: 2 procedure questions and 8 reset requests. Of the 8
   resets, 7 were completed, and of those 4 used a strong method and **3** did not.
7. **What the log can't tell you.** Whether the call-back really happened, or whether
   the agent chose the field value that let the ticket close. The same
   limitation as Day 04: the rule is only as honest as the field.

---

## Detection logic

**In plain English:** alert when the help desk **completes** a password or MFA
reset and the recorded verification method is **not** `DirectoryCallback` or
`VerifiedID`. Raise the severity to **High** if the same phone number made **two
or more procedure-question contacts** in the previous 24 hours, because that
matches the "learn the process first" pattern.

**KQL (Microsoft Sentinel, fictional custom table):**

```kql
// Help desk reset completed without a strong verification method
let strongMethods = dynamic(["DirectoryCallback", "VerifiedID"]);
let probes = NorthwindHelpdesk_CL
    | where TimeGenerated > ago(2d)
    | where RequestType == "ProcedureQuestion"
    | project ProbeTime = TimeGenerated, CallerNumber;
NorthwindHelpdesk_CL
| where TimeGenerated > ago(1d)
| where RequestType in ("PasswordReset", "MfaReset") and Outcome == "Completed"
| where VerificationMethod !in (strongMethods)
| join kind=leftouter probes on CallerNumber
| extend IsPriorProbe = isnotnull(ProbeTime)
        and ProbeTime < TimeGenerated
        and ProbeTime > TimeGenerated - 1d
| summarize PriorProbes = countif(IsPriorProbe)
    by TicketId, TimeGenerated, Agent, Employee, CallerNumber,
       NumberInDirectory, RequestType, VerificationMethod
| extend Severity = iff(PriorProbes >= 2, "High", "Medium")
```

I ran the same logic over the sample rows in Python. It returns **3** of the 10
rows:

```
TicketId  Employee   RequestType  VerificationMethod  PriorProbes  Severity
HD-8804   dana.lee   MfaReset     KnowledgeQuestions  2            High
HD-8806   p.shah     PasswordReset KnowledgeQuestions 0            Medium
HD-8807   l.martin   MfaReset     CallerIdMatch       0            Medium
```

Why the other seven drop out:

- **HD-8801 and HD-8802** are procedure questions, not resets.
- **HD-8803, HD-8805, HD-8808 and HD-8810** used a strong method.
- **HD-8809** was **Declined**, so the control worked and there's nothing to chase.

Details about the query:

- `!in` is the negated form of `in` and is case-sensitive, so `directorycallback`
  would count as weak. Standardise the values at the source.
- The left outer join keeps resets with no probes (`ProbeTime` is null), and
  `countif` then returns 0 for them. Joining on `CallerNumber` only means a shared
  number, such as a switchboard or a co-working space, could inflate the count.
- A real deployment should also confirm that the reset actually happened in
  Entra ID by looking for the audit event `Reset password (by admin)` in
  `AuditLogs`, in the category Microsoft documents as `UserManagement`. Check
  exact operation names in your own tenant before relying on them.

**Tuning note:** this alerts on 3 of 8 reset requests in the sample, which would be
far too noisy in a real organisation if weak methods were common, so the first
output of the rule is really a measurement of how much of your process is weak.
Treat it as a gap report before an alert. Expect most Medium hits to be real staff
travelling or stuck, so they need a review and a follow-up (re-verify through a
strong method after the fact), not an incident. Don't allow-list agents, because
the alert is about the process, not the person. The better outcome is a ticket
system that **cannot** close a reset without a strong method, with an exception
path that someone other than the requester approves. And never suppress a
`PriorProbes >= 2` hit because the verification method looked fine, since the
method field is typed by the agent.

---

## Your turn

1. Explain in your own words why knowledge questions and a matching caller ID
   don't verify a caller. For each, what would an attacker need to do to pass?
2. HD-8806 (p.shah) was genuine. Write the policy you would give the help desk for
   an employee who has lost their phone and is overseas. What do they do, step by
   step, and what is the slowest part?
3. The two probing calls (HD-8801, HD-8802) got answers. What should an agent be
   allowed to say about the reset procedure to an unverified caller? Write the
   script in two or three sentences.
4. Northwind's CEO calls the help desk locked out, in a hurry, and says "just do
   it." Write the exact words the agent says, and the escalation path that
   protects the agent afterwards.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- CISA, FBI and partners: [Scattered Spider advisory](https://www.ic3.gov/CSA/2025/250729.pdf) (updated 29 July 2025)
- Microsoft Learn: [Verified help desk with Microsoft Entra Verified ID](https://learn.microsoft.com/en-us/entra/verified-id/helpdesk-with-verified-id)
- Microsoft Learn: [Configure a Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
- Microsoft Learn: [Microsoft Entra audit log activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities)
- This log: [ANALYSIS.md](../ANALYSIS.md) (the help desk section) · [Day 02](2026-11-04-voice-cloning-limits.md) (why a convincing voice proves nothing) · [Day 04](2026-11-06-payment-controls-callbacks-dual-approval.md) (a completed field is a claim, not evidence)

⬅️ [Learning log index](README.md) · ➡️ [Day 06: Phishing-resistant MFA and the recovery path (8 Nov)](2026-11-08-phishing-resistant-mfa-recovery-path.md)
