# DAY ONE Deepfake BEC: Anatomy of the Attack

📅 3 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Business email compromise (**BEC**) is when a criminal poses as someone you
trust to get money or data. In 2025 the FBI recorded about **US$3.05 billion**
in BEC losses, and a little over **US$30 million** of that had a confirmed AI
component. That AI figure is a floor, because victims can only report what they
noticed. A SOC analyst will rarely be handed a video file to analyse. You'll
see the **email, the login, the payment record**, so today is about where
a deepfake fits in the attack chain and which logs still tell the truth.

---

## The concept

### The deepfake is one link in a chain

Think of a deepfake as an **objection handler**. It exists to answer the
victim's doubt, not to do the stealing. The money still moves through normal
payment systems, and those leave records.

| Stage | What the attacker does | ATT&CK | Where it shows up |
|---|---|---|---|
| **1. Research** | Finds names, reporting lines, voice and video samples online | Reconnaissance | Mostly invisible to you |
| **2. Prepare** | Registers a lookalike domain, builds a cloned voice or video | [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Possibly threat intel |
| **3. First contact** | Email or WhatsApp with a confidential, urgent request | [T1566](https://attack.mitre.org/techniques/T1566/), [T1656](https://attack.mitre.org/techniques/T1656/) | Email logs |
| **4. Remove doubt** | Voice call or video meeting using the fake | [T1566.004](https://attack.mitre.org/techniques/T1566/004/) | Meeting and call records, if not on a personal phone |
| **5. Get the money** | Victim creates or changes a payment | [T1657](https://attack.mitre.org/techniques/T1657/) | Finance system and bank portal |

> 💡 **The analyst's shortcut:** don't try to prove a face is fake. Ask *"is the
> request real?"* You can answer that from a phone directory and a payment log.

### What real cases show

| Case | What happened | The lesson |
|---|---|---|
| **Arup (2024)** | An employee doubted an email, then a video call with apparent senior staff convinced them. 15 payments to 5 accounts, about US$25m | The fake answered the doubt. Police said they believed existing videos were reused with AI voices added |
| **Ferrari (2024)** | WhatsApp messages and a cloned CEO voice from new numbers | One private question ended the call |
| **LastPass (2024)** | Deepfake voicemail on WhatsApp posing as the CEO | The wrong channel gave it away, and the employee reported it |

### Why MFA doesn't save you here

MFA proves the **account holder** signed in. In an Arup-style case the
legitimate employee signs in on their own laptop and makes the payment
themselves. Every identity log looks clean. That's why this attack is stopped
by **business process** controls.

| Control | What it does |
|---|---|
| **Call-back** | Verifier phones a number from the HR directory, never one from the message |
| **Dual approval** | The system refuses to release a payment without a second, independent person |
| **New-payee hold** | First payment to new bank details waits for a check |
| **Confirmation of Payee** | The bank compares the account name with the details entered. In Australia it's a warning, not a block |

---

## Sample logs

All times are UTC on **Monday 2 November 2026**. 00:41 UTC is **11:41 in Sydney**
(AEDT, UTC+11). All data is fictional. `ben.okafor` works in accounts payable,
`sara.lund` is the finance manager and payment approver, and `helen.marsh` is
Northwind's real CFO. `NorthwindPayments_CL` is a fictional custom table fed
from the finance system.

**Email** (`EmailEvents`, simplified, 5 rows). `Auth` summarises SPF/DKIM/DMARC.

```
Timestamp (UTC)      EmailDirection  SenderFromAddress                          RecipientEmailAddress             Subject                   DeliveryAction  Auth
2026-11-02 00:14:22  Inbound         accounts@fabrikam-supplies.example         ben.okafor@northwind-example.com  October statement         Delivered       pass/pass/pass
2026-11-02 00:41:09  Inbound         helen.marsh@northwind-advisory.example     ben.okafor@northwind-example.com  Confidential: Project Karri  Delivered    pass/pass/pass
2026-11-02 00:58:31  Inbound         quotes@fresh-catering.example              sara.lund@northwind-example.com   Catering quote            Delivered       pass/pass/pass
2026-11-02 01:07:15  Inbound         helen.marsh@northwind-advisory.example     ben.okafor@northwind-example.com  Project Karri: join now   Delivered       pass/pass/pass
2026-11-02 02:20:02  Intra-org       helen.marsh@northwind-example.com          sara.lund@northwind-example.com   I did not request PAY-3381  Delivered     (internal)
```

**Meeting attendance** (simplified export, 4 rows):

```
Time (UTC)  Event   DisplayName         ParticipantType  Video
01:29:41    Joined  Helen Marsh         External         On
01:29:44    Joined  Mark Tran (Legal)   External         Off
01:30:04    Joined  Ben Okafor          Internal         On
01:41:50    Left    Ben Okafor          Internal         -
```

**Payments** (`NorthwindPayments_CL`, 4 rows):

```
TimeGenerated (UTC)  PaymentId  Preparer                          Beneficiary            AmountAUD  BankAccountAgeDays  FinalStatus
2026-11-02 00:30:12  PAY-3379   ben.okafor@northwind-example.com  Fabrikam Supplies      41250      412                 Released
2026-11-02 00:52:48  PAY-3380   priya.nair@northwind-example.com  Fresh Catering         12400      0                   Released
2026-11-02 01:52:40  PAY-3381   ben.okafor@northwind-example.com  Karri Advisory         186400     0                   Rejected
2026-11-02 03:05:17  PAY-3382   priya.nair@northwind-example.com  Bluegum Logistics      64000      2                   Released
```

Context you already have: `fabrikam-supplies.example` is an existing supplier
seen for months. **VEND-771** is a completed onboarding record for Bluegum
Logistics, with bank details confirmed by phone. At 02:12:30 UTC, `sara.lund`
rang Helen on her **directory** number, and Helen said she knew nothing about it.
Sara rejected PAY-3381 at 02:18:05.

---

## What to look for

1. **Authentication passed, and that means little.** All **4** inbound emails
   pass SPF, DKIM and DMARC. As with last month's lookalike supplier, the
   attacker owns `northwind-advisory.example`, so *pass* only proves the mail
   really came from that domain.
2. **Real name, wrong domain.** The display address uses `helen.marsh` on a
   domain Northwind doesn't own. The real CFO's mail in row 5 is **Intra-org**
   from `northwind-example.com`.
3. **Secrecy plus urgency.** "Confidential" and "join now" arrive **26 min 6 s**
   apart. Confidentiality matters to the attacker because it stops the victim
   from checking with colleagues.
4. **A new channel, from outside.** Both other participants are **External**,
   and one has video off. Ben's call lasted **11 min 46 s**. The log can't tell
   you whether the video was fake, and it doesn't need to. The CFO doesn't run
   internal meetings from an external tenant.
5. **The money follows the story.** PAY-3381 was created **1 h 11 min 31 s**
   after first contact and **45 min 25 s** after the last email: **AUD 186,400**
   to a bank account first used that day. That's the strongest signal in the
   dataset.
6. **The control worked, and it wasn't technical.** Sara's call-back came
   **19 min 50 s** after the payment was created. Ben was fooled and did nothing
   wicked, so this is a process win, not a user failure to punish.
7. **Rule things out.** PAY-3379 is an established account. PAY-3380 is small.
   PAY-3382 is large and new, but has an onboarding record and no suspicious mail
   to Priya. `fresh-catering.example` is a new domain, but it's a quote sent to
   someone who didn't prepare a large new-payee payment.

---

## Detection logic

**In plain English:** alert when a user prepares a **large payment** to a
**recently added bank account** within **24 hours** of receiving mail from a
domain Northwind has **not seen before**. Each half alone is noisy. New
domains and new payees happen every day, but the combination is what BEC looks like.

**KQL (Microsoft Sentinel, with Defender XDR `EmailEvents` and a custom payments
table):**

```kql
// Large payment to a new bank account soon after mail from a never-seen domain
let lookback = 30d;
let recent = 3d;
let contactWindow = 24h;
let minAmount = 50000;
let maxAccountAgeDays = 7;
let knownDomains =
    EmailEvents
    | where Timestamp between (ago(lookback) .. ago(recent))
    | where EmailDirection == "Inbound"
    | distinct SenderFromDomain;
let newDomainMail =
    EmailEvents
    | where Timestamp > ago(recent)
    | where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
    | where SenderFromDomain !in (knownDomains)
    | project EmailTime = Timestamp, Upn = tolower(RecipientEmailAddress),
              SenderFromDomain, Subject;
NorthwindPayments_CL
| where TimeGenerated > ago(recent)
| where AmountAUD >= minAmount and BankAccountAgeDays <= maxAccountAgeDays
| extend Upn = tolower(Preparer)
| join kind=inner newDomainMail on Upn
| where TimeGenerated between (EmailTime .. (EmailTime + contactWindow))
| summarize FirstContact = min(EmailTime), Emails = count(),
            Domains = make_set(SenderFromDomain)
          by PaymentId, Upn, Beneficiary, AmountAUD, PaymentTime = TimeGenerated
```

On the sample it returns **1** row:

```
PaymentId  Upn                               Beneficiary     AmountAUD  PaymentTime          FirstContact         Emails  Domains
PAY-3381   ben.okafor@northwind-example.com  Karri Advisory  186400     2026-11-02 01:52:40  2026-11-02 00:41:09  2       ["northwind-advisory.example"]
```

Why the others drop out: PAY-3379 and PAY-3380 fail the amount or account-age
test. PAY-3382 passes both, but Priya received **0** new-domain emails.
**3** inbound emails came from new domains, but the catering mail went to
`sara.lund`, who prepared no payment.

How it works:

- `knownDomains` builds a baseline from **27 days** of mail, stopping 3 days ago
  so that today's lookalike can't approve itself.
- `!in (knownDomains)` keeps only domains missing from that baseline.
- `kind=inner` keeps every matching email, so `Emails` shows how much contact
  there was. As on last month's Day 20, the KQL default (`innerunique`) could
  hide rows.
- `summarize` turns those pairs back into **one row per payment**, so one
  incident means one alert.

**Tuning note:** the thresholds are starting points. AUD 50,000 suits Northwind,
and split payments (remember Arup's 15) can dodge it, so a companion rule should
sum payments per beneficiary over 7 days. A user who received the mail on a
personal phone or WhatsApp leaves no trace here at all, which is why a
payment-side rule on new beneficiaries is still worth having by itself at lower
severity. Allow-list by **vendor onboarding record**, not by domain. This rule
only works if finance data reaches the SIEM, and getting that feed is often the
real project. When it fires, phone the approver **first**: speed matters more
than proof while the money is still in your account.

---

## Your turn

1. In your own words, explain why every email passing SPF, DKIM and DMARC
   doesn't clear this case. What would you check instead?
2. Build the timeline from 00:41:09 to 02:20:02, in **UTC** with the **Sydney**
   time in brackets, and tag each step with its stage from today's chain table.
3. PAY-3382 is large, to a new account, and released. Write the 2–3 checks you'd
   make before calling it benign. Would you change the rule because of it?
4. Suppose Ben had been told the same story over **WhatsApp** on his personal
   phone. Which sample logs vanish, which remain, and which control still works?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- FBI IC3 2025 figures: [The Record](https://therecord.media/cyber-fraud-surges-to-17-billion-fbi-ic3) · [SecureWorld summary](https://www.secureworld.io/industry-news/ai-enabled-fraud-topped-893m-fbi)
- Case reports: [Arup-style deepfake meeting (BankInfoSecurity)](https://www.bankinfosecurity.com/fraudsters-deepfake-entire-meeting-swindle-255m-a-24273) · [Ferrari (Fortune)](https://fortune.com/2024/07/27/ferrari-deepfake-attempt-scammer-security-question-ceo-benedetto-vigna-cybersecurity-ai) · [LastPass](https://blog.lastpass.com/posts/attempted-audio-deepfake-call-targets-lastpass-employee)
- Australian Banking Association: [Confirmation of Payee](https://www.ausbanking.org.au/scam-safe-accord/confirmation-of-payee/)
- Microsoft Learn: [EmailEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table) · [join operator (KQL)](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- MITRE ATT&CK: [T1566.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/) · [T1656 Impersonation](https://attack.mitre.org/techniques/T1656/) · [T1657 Financial Theft](https://attack.mitre.org/techniques/T1657/)

⬅️ [Learning log index](README.md) · ➡️ [Day 02: Voice cloning: what it takes and where it breaks (4 Nov)](2026-11-04-voice-cloning-limits.md)
