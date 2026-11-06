# Day 04 — Payment Controls That Stop BEC: Call-backs and Dual Approval

📅 6 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Days 01 to 03 kept arriving at the same answer: you can't judge the face, the
voice or the email, so authenticate the **transaction**. Today is that answer in
detail. The two controls that do most of the work are the **call-back** (phone the
real person on a number you already trust) and **dual approval** (a second,
independent person releases the money).

Both are old, cheap and well known, so why do they still fail? Because they are
usually written down as policy and then left to people under time pressure. A
control that lives only in a procedure document can be skipped, and the
payment record will happily show it was skipped. That record is what a SOC can
actually see, so this entry is about turning "we have a call-back policy" into
something you can measure and alert on.

---

## The concept

### A call-back is only as good as the phone number

The idea is simple: confirm a request by contacting the person using contact
details you already hold. The Australian Signals Directorate's guidance says to
[establish a clear and consistent business process](https://www.cyber.gov.au/publication/protecting-against-business-email-compromise)
for verifying payment requests, and to use contact details you have verified
separately, for example a number from the organisation's official website. It also
lists warning signs: an unexpected change of bank details, an urgent request or
threats of consequences, an unusual request from someone in authority, and a
sender domain that doesn't quite match the supplier.

JPMorgan, a bank, publishes four common ways
[call-backs go wrong](https://www.jpmorgan.com/insights/cybersecurity/business-email-compromise/when-callbacks-go-wrong).
That's bank guidance, not an independent study, but each point is easy to see in a log:

| Mistake | Why it fails | What a log could show |
|---|---|---|
| **Relying on an inbound call** | A fraudster who has taken over a vendor's email may also ring you, knowing a call-back is part of your controls | `CallbackNumberSource = InboundCall` |
| **Using a number from the email or invoice** | If the email is the attacker's, so is the number in it | `CallbackNumberSource = EmailSignature` |
| **Speaking to the wrong person** | A compromised mailbox can intercept the hand-off and a colleague "confirms" | Who was called isn't usually logged, which is a gap |
| **Assuming the steps were followed** | When the bank flags a payment, someone has to check that the call-back really happened | A completed field that nobody verified |

> 💡 **Judgement call:** the fourth row matters most to a SOC. A tick-box that says
> "call-back done" is a claim, not evidence. It's only as strong as the system that
> sets it.

### Dual approval: two people, two logins, enforced by the tool

Dual control means the person who **prepares** a payment can't be the person who
**releases** it. Done properly, the payment portal itself refuses to release
without a second, different user. ANALYSIS.md lists the usual failure: the
rule lives in policy rather than the tool, so the approver "just approves" because the
preparer said the CFO had confirmed. Three weaker variants to watch for:

| Weak version | What goes wrong |
|---|---|
| **Same person, two roles** | An admin or override path lets one user prepare and approve. The control exists on paper only |
| **Rubber-stamp approval** | The approver releases within minutes, with nothing to show they looked at anything. Speed isn't proof, but it's a prompt to sample |
| **Shared evidence, not independent checks** | The approver relies on the preparer's note that the call-back was done, so there are still two signatures but only one check |

### Where Confirmation of Payee fits

In Australia, [Confirmation of Payee](https://www.ausbanking.org.au/scam-safe-accord/confirmation-of-payee/)
(CoP) checks the account name you entered against the receiving bank's records
and returns a match, close match or no match. The Australian Banking Association
says it began rolling out in July 2025 and is now live at more than 100 financial
institutions (the ABA's own figures, as at July 2026). Its own page says three
things worth keeping in mind:

- It's **advisory, not a hard block**: you can continue after a close match or no match.
- It's **domestic only**, for payments made with a BSB and account number.
- A mismatch has innocent causes, such as a business trading under another name, so people see warnings that are often harmless.

So treat a "no match" like a failed call-back signal: stop and check through a
trusted channel. And remember what it can't do. If the attacker's account really is
named "Coastal Packaging", the name matches. CoP checks the *name* against the
account, not whether the *change of account* was legitimate. Only the call-back
answers that.

### Making the controls enforceable

| Control | Weak form | Strong form |
|---|---|---|
| **Call-back** | A free-text note or tick-box | The payment can't move to "approved" until a call-back record exists, with the number's source taken from a system of record |
| **Dual approval** | Policy says two people | The portal blocks release when preparer and approver are the same identity, with no admin override |
| **New-payee hold** | Everyone knows to be careful | An automatic hold on the first payment to new bank details |
| **Exceptions** | Verbal "just this once" | An exception workflow that someone other than the requester must approve, and that gets reported |

Be candid about the cost. Call-backs slow urgent payments, vendor contacts go
stale, and a rule with no exceptions will be worked around the first time a real
emergency lands. That's why an exception path with a record is better than
a rule that people quietly break.

---

## Sample logs

All times are UTC on **Thursday 5 November 2026**. Sydney is UTC+11, so 02:10 UTC
is **13:10 in Sydney**. All data is fictional. `NorthwindPayments_CL` is the
**fictional custom table** from Days 01 and 03, extended with `PreparedTime`,
`CallbackNumberSource` and an `Approver` that can equal the `Preparer`. Real
Sentinel custom tables usually carry type suffixes such as `_s` or `_d`, which I've
left off, and no finance product logs exactly this.

`CallbackNumberSource` is where the number came from: `VendorMaster` and
`Directory` are systems of record, `EmailSignature` and `InboundCall` are not, and
`None` means no call-back was made. Users are shortened to first names.

**Payments** (`NorthwindPayments_CL`, 8 rows):

```
PaymentId  Preparer  Approver  Beneficiary          AmountAUD  AcctAgeDays  CallbackStatus  CallbackNumberSource  PreparedTime (UTC)  ApprovalTime (UTC)  FinalStatus
PAY-3410   ben       sara      Fabrikam Supplies    41250      412          Completed       VendorMaster          2026-11-05 00:30    2026-11-05 00:52    Released
PAY-3411   priya     david     Redgum Supplies      58000      2            Completed       VendorMaster          2026-11-05 01:05    2026-11-05 01:40    Released
PAY-3412   ben       sara      Coastal Packaging    96000      0            Completed       EmailSignature        2026-11-05 02:10    2026-11-05 02:14    Released
PAY-3413   priya     priya     Lakeside Consulting  130000     0            Completed       VendorMaster          2026-11-05 02:30    2026-11-05 02:33    Released
PAY-3414   ben       david     Harbour Freight      64000      1            Skipped         None                  2026-11-05 03:00    2026-11-05 03:03    Released
PAY-3415   ben       sara      Green Valley Print   8200       40           Skipped         None                  2026-11-05 03:20    2026-11-05 03:25    Released
PAY-3416   priya     sara      Ironbark Hardware    77000      0            Completed       InboundCall           2026-11-05 03:40    2026-11-05 03:46    Released
PAY-3417   ben       sara      Karri Advisory       186400     0            Completed       Directory             2026-11-05 04:00    2026-11-05 04:25    Rejected
```

What was found out later (fictional): the real supplier behind PAY-3412 had never
asked for new bank details, and the "confirmation" came from a number in the
fraudster's email. The AUD 130,000 payment to Lakeside Consulting turned out to be
a legitimate invoice that priya released herself through an admin override. The
others were genuine except PAY-3417, which the approver rejected after
phoning the real contact from the directory.

---

## What to look for

1. **The control that worked.** PAY-3411 (AUD 58,000, account age **2** days) has
   a completed call-back to a `VendorMaster` number, a different approver and a
   **35-minute** gap. A new account isn't a problem when the control ran properly.
   PAY-3417 (**AUD 186,400**, age 0) was **Rejected** after a call-back to the
   `Directory`: that's the Day 01 pattern, stopped.
2. **A completed call-back to the wrong number.** PAY-3412 says **Completed**
   but the number came from an `EmailSignature`. This is the one a simple
   `CallbackStatus != "Completed"` rule would miss, and the loss in this scenario.
3. **One person, two roles.** PAY-3413 has `Preparer = Approver` (priya) for
   **AUD 130,000**. Even though it turned out legitimate, the control that was
   supposed to prevent a single point of failure didn't operate. Judge it by the
   control, not by the outcome.
4. **A skipped call-back.** PAY-3414 (**AUD 64,000**, age 1) was approved
   **3 minutes** after being prepared with no call-back at all.
5. **An inbound call counted as verification.** PAY-3416 (**AUD 77,000**, age 0)
   records `InboundCall`, which is the first mistake in the table above.
6. **Fast approvals are a clue, not proof.** The four alerts were approved in
   **3 to 6 minutes**, against **22** and **35** minutes for the two payments
   (PAY-3410 and PAY-3411) that had a proper call-back. Five rows prove nothing, but speed is a good thing
   to sample.
7. **Rule things out on purpose.** PAY-3410 (AUD 41,250) is under the amount
   threshold and had a proper call-back anyway. PAY-3415 (**AUD 8,200**) also
   skipped the call-back, but whether small payments need one is a policy
   decision, so the rule leaves it out. PAY-3417 is not **Released**, so there's
   nothing to alert on.
8. **What the log can't tell you.** Whether the call actually happened, who
   answered, and whether the person answering was the right one. If
   `CallbackNumberSource` is a drop-down the preparer fills in, they can pick
   `VendorMaster` without calling anyone. This is a limitation of the data, not
   something the rule can fix.

---

## Detection logic

**In plain English:** alert when a payment of **AUD 50,000 or more** is
**released** and either (a) the preparer and approver are the **same person**, or
(b) the call-back was **not completed**, or (c) it was completed using a number
that **didn't come from a system of record**. One rule covers the three ways the
controls from the concept section can be bypassed, and the alert says which.

**KQL (Microsoft Sentinel, fictional custom table):**

```kql
// Large payment released without a trustworthy call-back or independent approval
let minAmount = 50000;
let trustedSources = dynamic(["VendorMaster", "Directory"]);
NorthwindPayments_CL
| where ApprovalTime > ago(1d)
| where FinalStatus == "Released" and AmountAUD >= minAmount
| extend SelfApproved = tolower(Preparer) == tolower(Approver)
| extend CallbackOk = CallbackStatus == "Completed" and CallbackNumberSource in (trustedSources)
| where SelfApproved or not(CallbackOk)
| extend Reason = case(
    SelfApproved, "Self-approved",
    CallbackStatus != "Completed", "Call-back not completed",
    "Call-back number not from a system of record")
| extend ApprovalGapMin = datetime_diff("minute", ApprovalTime, PreparedTime)
| project PaymentId, Beneficiary, AmountAUD, AcctAgeDays, Preparer, Approver,
          CallbackStatus, CallbackNumberSource, ApprovalGapMin, Reason
```

I ran the same logic over the sample rows in Python. It returns **4** of the 8 rows,
a total of **AUD 367,000**:

```
PaymentId  Beneficiary          AmountAUD  AcctAgeDays  Reason                                       ApprovalGapMin
PAY-3412   Coastal Packaging    96000      0            Call-back number not from a system of record  4
PAY-3413   Lakeside Consulting  130000     0            Self-approved                                 3
PAY-3414   Harbour Freight      64000      1            Call-back not completed                       3
PAY-3416   Ironbark Hardware    77000      0            Call-back number not from a system of record  6
```

Why the other four drop out:

- **PAY-3410** is under AUD 50,000.
- **PAY-3411** passes every test: two people, a completed call-back to a system-of-record number.
- **PAY-3415** is under AUD 50,000, even though its call-back was skipped.
- **PAY-3417** is **Rejected**, not **Released**.

A few details about the query:

- `case()` picks the first matching reason, so PAY-3413's self-approval is
  reported even though its call-back was fine. If a payment fails more than one
  test, only the first is shown. Add separate boolean columns if you want all of them.
- `in (trustedSources)` is case-sensitive, so `vendormaster` would not match.
  Normalise the values in the source or use `in~`.
- `datetime_diff("minute", a, b)` returns `a - b`, so the gap is positive when
  approval comes after preparation.

**Tuning note:** AUD 50,000 is a starting point carried over from earlier days, not a
measured value. Split payments dodge a single-payment threshold, so add a companion
rule summing releases per beneficiary over 7 days. The rule is only as honest as
`CallbackNumberSource`. If staff can type it, expect the field to say whatever
passes, and the real fix is to populate it from the system of record
automatically. Expect some noise from legitimate emergency overrides, so give them
their own workflow and report them, rather than allow-listing a person. The
better outcome is a portal that **cannot** release these payments, so that the
alert becomes a backstop rather than the control. Finally, sample the
payments that did **not** alert: a clean-looking record with a 3-minute approval
deserves an occasional human look.

---

## Your turn

1. In your own words, why is a payment with `CallbackStatus = Completed` still
   not safe? List two ways the call-back could be completed and still be useless.
2. PAY-3413 was a legitimate invoice, yet it appears in the alert. Argue both
   sides: should this be a high-severity alert or a lower one, and why?
3. Pick one of the four alerts and write the first three things you would do
   within the first 15 minutes, in order. Who do you phone, and on what number?
4. Northwind's finance manager says the call-back requirement is "slowing
   things down" and wants it removed for suppliers under 90 days old. Write a short,
   non-hostile reply that names the trade-off and proposes something other than
   removal.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- ASD / Australian Cyber Security Centre: [Protecting against business email compromise](https://www.cyber.gov.au/publication/protecting-against-business-email-compromise)
- Bank guidance (JPMorgan): [When callbacks go wrong](https://www.jpmorgan.com/insights/cybersecurity/business-email-compromise/when-callbacks-go-wrong)
- Australian Banking Association: [Confirmation of Payee](https://www.ausbanking.org.au/scam-safe-accord/confirmation-of-payee/)
- Microsoft Learn: [join operator (KQL)](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- MITRE ATT&CK: [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657/)
- This log: [ANALYSIS.md](../ANALYSIS.md) (the controls table in section 1) · [Day 03](2026-11-05-why-people-and-detectors-miss-fakes.md) (skipped call-backs after a "Likely real" verdict)

⬅️ [Learning log index](README.md) · ➡️ [Day 05: Help desk social engineering and verifying a caller (7 Nov)](2026-11-07-help-desk-social-engineering.md)
