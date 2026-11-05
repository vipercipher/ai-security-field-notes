# Day 02 — Voice Cloning: What It Takes and Where It Breaks

📅 4 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Yesterday's lesson said a deepfake is an objection handler. Voice is the
cheapest one to build, because a phone call needs no video, no meeting invite and
no lookalike domain. It is also the one analysts see least. Calls to a mobile
phone leave no email, no login and no recording in your SIEM.

So today has two jobs. The first is to be honest about **how little it takes** to
copy a voice well enough to fool a hurried colleague. The second is to find
**where the attack is weak**, because those weak spots are where your controls and
your logs can do real work. The conclusion is the same as Day 01: you can't judge
a voice, but you can judge the request.

---

## The concept

### What it takes (at the level a defender needs)

This is not a how-to. The point is the *cost*, because that decides who can attack you.

| Ingredient | What published sources say | What it means for you |
|---|---|---|
| **Audio of the target** | Microsoft's VALL-E research paper describes a model that, given a **3-second** recording of an unseen speaker as a prompt, synthesises speech in that voice. It was trained on 60,000 hours of English speech | That's a research result, not a product. It shows the direction: less audio each year. Executives with conference talks, podcasts and earnings calls have hours of it public |
| **A tool** | In 2023 a Guardian Australia journalist cloned their own voice from about **4 minutes** of audio using a free online tool | The tooling is not a barrier. Assume anyone can get it |
| **A consent check** | In a March 2025 Consumer Reports review of six voice-cloning products, **4 of 6** (ElevenLabs, Speechify, PlayHT, Lovo) relied on the user ticking a box to say they had the right to clone the voice. Descript and Resemble AI had stronger consent steps, which the review said were not foolproof | Vendor safeguards are uneven and change over time, so they are not part of your defence. Products may have changed since the review |
| **A reason for you to answer** | A pretext, urgency, and a channel your controls don't cover | This is the real work, and it's the same as ordinary fraud |

> 💡 **The cost curve matters more than the quality.** A mediocre clone from a
> stranger's phone call is enough if the story is good. A perfect clone is wasted
> if the payment process won't release the money.

### Where it breaks

A cloned voice has real weak points. Treat these as places to look, **not** as
things to rely on.

| Weak point | Why it's hard for the attacker | Why you still can't rely on it |
|---|---|---|
| **Live conversation** | A clone that reads a script is easy. Unscripted back-and-forth is harder, and my judgement is that long pauses and odd answers are the likeliest slips. In the Ferrari case, one private question (about a book the CEO had recommended) ended the call | It worked once, on a prepared executive. Attackers can also use pre-generated clips, a bad-line excuse, or a voicemail so there is no conversation at all |
| **Phone audio quality** | Phone calls squeeze speech through narrow codecs. That hides some of the tells a detector uses | It cuts both ways. In the ASVspoof 5 challenge (a research evaluation of spoofing and deepfake detectors), narrowband 8 kHz codecs and neural compression were among the hardest conditions for the top systems. The 2024 Deepfake-Eval-2024 benchmark also found open-source audio detectors lost about 48% of their AUC on real-world content compared with their original benchmarks. Bad lines help the attacker |
| **Private knowledge** | A voice doesn't know what the real person knows. The caller can't answer "what did we agree last Thursday?" | Anything public, or anything in a stolen mailbox, is fair game. Ask something recent *and* private, and treat it as a backstop |
| **The channel** | The attacker has to reach you from somewhere. A new number, a personal WhatsApp or an unexpected mobile is often the giveaway (Ferrari and LastPass both involved one) | Caller ID can be faked. The Australian regulator, ACMA, says overstamping a number is legal unless done for unlawful or malicious purposes, so a number that *looks* right proves little |
| **The payment process** | A call can't release money from a portal that needs a second approver and a new-payee hold | This is the one that holds. It doesn't care how good the voice was |

### The special case: voice as a password

Some organisations use the voice itself to prove identity. This is the one place
where cloning attacks a *control* directly, not just a person.

- In March 2023 Guardian Australia reported that the cloned voice, plus the
  journalist's customer reference number, got into a Centrelink self-service account.
  The same report said the ATO's voiceprint system was also reportedly fooled. Services Australia
  said the system was secure and that it continually assesses risks. I haven't checked whether
  either agency has changed its approach since, so treat that as a 2023 snapshot.
- The lesson is general: a voiceprint is a *biometric match*, and a good enough
  copy of the biometric matches. If you run one, treat it as one weak signal
  among several, never as the only gate for a sensitive change.

---

## Sample logs

All times are UTC on **Tuesday 3 November 2026** (the day after Day 01).
Sydney is UTC+11, so 03:40 UTC is **14:40 in Sydney**. All data is fictional,
including the phone numbers. `NorthwindVoice_CL` and the extended
`NorthwindPayments_CL` are **fictional custom tables**. Real column names depend on
your phone system and finance feed, and custom Sentinel columns often carry type
suffixes such as `_s` or `_d`. I've left those off for readability.
`DirectoryMatch` says whether the **external party's** number is in the HR/vendor directory.
`sara.lund` is the payment approver.

**Calls** (`NorthwindVoice_CL`, 6 rows):

```
TimeGenerated (UTC)  CallId  Direction  Channel  CallerNumber      CalleeUpn                           DurationSec  DirectoryMatch
2026-11-03 03:02:41  C-9001  Inbound    PSTN     +61 491 570 157   sara.lund@northwind-example.com     212          Yes
2026-11-03 03:40:15  C-9002  Inbound    PSTN     +61 491 570 158   sara.lund@northwind-example.com     301          No
2026-11-03 04:10:02  C-9003  Inbound    PSTN     +61 491 570 313   priya.nair@northwind-example.com    164          No
2026-11-03 04:15:30  C-9004  Inbound    PSTN     +61 491 570 158   sara.lund@northwind-example.com     148          No
2026-11-03 04:25:05  C-9005  Inbound    PSTN     +61 491 570 159   sara.lund@northwind-example.com     38           No
2026-11-03 05:02:12  C-9006  Outbound   PSTN     +61 2 5550 0100   helen.marsh@northwind-example.com   41           Yes
```

**Payments** (`NorthwindPayments_CL`, now with `Approver` and `ApprovalTime`, 4 rows):

```
PaymentId  Preparer                          Approver                          Beneficiary         AmountAUD  BankAccountAgeDays  ApprovalTime (UTC)   FinalStatus
PAY-3390   priya.nair@northwind-example.com  sara.lund@northwind-example.com   Bluegum Logistics   72000      3                   2026-11-03 03:20:44  Released
PAY-3391   ben.okafor@northwind-example.com  sara.lund@northwind-example.com   Wattle Advisory     148500     0                   2026-11-03 04:31:20  Rejected
PAY-3392   priya.nair@northwind-example.com  sara.lund@northwind-example.com   Fresh Catering      12400      0                   2026-11-03 04:20:10  Released
PAY-3393   priya.nair@northwind-example.com  david.cho@northwind-example.com   Harbour Freight     64000      1                   2026-11-03 04:50:33  Released
```

Context you already have: `+61 491 570 157` is Helen Marsh's mobile in the HR
directory, and she did ring Sara at 03:02 UTC about routine payments. Bluegum
Logistics has a completed onboarding record (VEND-771, Day 01). The call at 05:02:12
UTC was Sara ringing Helen back on her **directory** number. Helen knew nothing
about Wattle Advisory, and PAY-3391 was rejected.

---

## What to look for

1. **Not every unknown caller matters.** Of the **5** inbound calls, **4** come from
   numbers outside the directory. That's too many to alert on by itself, because
   suppliers and customers ring from unknown numbers all day.
2. **The same unknown number twice.** `+61 491 570 158` rang Sara at 03:40:15 for
   **5 min 1 s**, then again at 04:15:30 for **2 min 28 s**, **35 min 15 s** later. A
   repeat call to the same approver fits someone pushing a request along.
3. **A call that is too short to matter.** C-9005 lasted **38 s**. That's a
   wrong number or a hang-up, not a conversation that could change a decision.
4. **Who got the calls.** C-9003 (164 s, unknown number) went to Priya. She isn't
   the approver on any payment that afternoon, so it needs no further thought here.
5. **The money follows the call.** PAY-3391 (**AUD 148,500**, bank account age
   **0** days) was approved **51 min 5 s** after the first call began and **13 min 22 s**
   after the second one ended. That's the strongest signal.
6. **The legitimate look-alike.** PAY-3390 is also large (**AUD 72,000**) and to
   an account only **3** days old. Sara approved it at 03:20:44, shortly after a call.
   But that call (C-9001) came from Helen's directory number, so it's different.
7. **The control that worked.** Sara's call-back (C-9006) used a **directory**
   number, not the caller's. It happened **30 min 52 s** after the approval, and the
   payment was rejected. The log shows the control, not the voice.
8. **What the logs can't tell you.** Nothing here says whether the voice was cloned.
   The attacker may have simply been convincing. You don't need to know. A
   spoofed caller ID could also make a call look like a directory match, which is
   the main blind spot of the rule below.

---

## Detection logic

**In plain English:** alert when an approver takes an inbound call from a number
**not in the directory** that lasts at least **2 minutes**, and then approves a
**large payment** to a **recently created bank account** within an hour of the call
ending. Unknown callers are normal, large payments are normal and new payees are
normal. The three together, in one person's hour, are what a voice-led BEC looks like.

**KQL (Microsoft Sentinel, fictional custom tables):**

```kql
// Approver takes an unknown-number call, then approves a large new-account payment
let minAmount = 50000;
let maxAccountAgeDays = 7;
let minCallSec = 120;
let window = 60m;
let UnknownCalls =
    NorthwindVoice_CL
    | where TimeGenerated > ago(2d)
    | where Direction == "Inbound" and Channel == "PSTN" and DirectoryMatch == "No"
    | where DurationSec >= minCallSec
    | project CallTime = TimeGenerated,
              CallEnd = TimeGenerated + DurationSec * 1s,
              CallerNumber, Upn = tolower(CalleeUpn);
NorthwindPayments_CL
| where ApprovalTime > ago(2d)
| where AmountAUD >= minAmount and BankAccountAgeDays <= maxAccountAgeDays
| extend Upn = tolower(Approver)
| join kind=inner UnknownCalls on Upn
| where ApprovalTime between (CallTime .. (CallEnd + window))
| summarize Calls = count(), FirstCall = min(CallTime),
            Callers = make_set(CallerNumber)
          by PaymentId, Upn, Beneficiary, AmountAUD, ApprovalTime
```

I ran the same logic over the sample rows in Python. It returns **1** row:

```
PaymentId  Upn                              Beneficiary      AmountAUD  ApprovalTime         Calls  FirstCall            Callers
PAY-3391   sara.lund@northwind-example.com  Wattle Advisory  148500     2026-11-03 04:31:20  2      2026-11-03 03:40:15  ["+61 491 570 158"]
```

Why everything else drops out:

- **C-9001** is dropped by `DirectoryMatch == "No"`, so PAY-3390 has no matching call.
- **C-9005** (38 s) is dropped by the 120-second test. The remaining unknown
  calls are C-9002, C-9003 and C-9004, so `Calls = 2` for PAY-3391 (C-9002 and C-9004).
- **C-9003** matches no payment, because its callee, Priya, approved nothing.
- **PAY-3392** fails the amount test (AUD 12,400). **PAY-3393** passes both
  payment tests, but David Cho took no unknown calls.

How it works:

- The `between` test starts at `CallTime` and not `CallEnd`, so an approval made
  *during* the call is still caught.
- The 60-minute window runs from `CallEnd`. For C-9002 the approval came 46 min 4 s
  after it ended, so a 30-minute window would have missed that call, though the
  second call (13 min 22 s) still triggers the alert.
- `kind=inner` keeps every matching call, so `Calls` shows how persistent the caller was.
- `summarize` returns one row per payment.

**Tuning note:** all thresholds are starting points, not measured values. The big
blind spot is that **caller ID can be faked**, so `DirectoryMatch == "Yes"` is not
proof, and a spoofed directory number sails past this rule. Treat the rule as one
layer. Another gap is mobile calls and WhatsApp that never touch your phone system, and
calls from the executive's *real* personal number that isn't in the directory
(false positives; fix the directory rather than the rule). Keep the directory fresh,
because a stale one makes this noisy. The first thing to do when it fires is the same
as Day 01: ring the named person on their **directory** number, before the money moves.
Also consider a lower-severity rule on any new-payee approval, regardless of calls.

---

## Your turn

1. In your own words, why does a cloned voice make **voice authentication** riskier
   than it makes a normal phone request? Which one is the control, and which is a person?
2. List the five "where it breaks" rows from today's table. For each one, say whether
   it is something an analyst can **log**, something a staff member can **do**, or neither.
3. In the sample, why is C-9001 not suspicious even though PAY-3390 is also large
   and to a new account? What single attacker trick would make it look the same, and
   what would still catch it?
4. Sara's call-back came 30 min 52 s after she approved. Rewrite the process so the
   call-back comes **before** approval and the system enforces it. What does that
   cost in speed, and who will complain?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Research: [VALL-E, "Neural Codec Language Models are Zero-Shot Text to Speech Synthesizers"](https://arxiv.org/pdf/2301.02111) (peer-reviewable preprint, research results)
- Consumer Reports: [Do these 6 AI voice cloning companies do enough to prevent misuse?](https://innovation.consumerreports.org/new-report-do-these-6-ai-voice-cloning-companies-do-enough-to-prevent-misuse/) · coverage in [The Register](https://www.theregister.com/2025/03/10/ai_voice_cloning_safeguards/)
- Guardian Australia's 2023 Centrelink test, as reported in [Cyber Daily](https://www.cyberdaily.au/government/8820-free-voice-ai-can-be-used-for-centrelink-fraud)
- Detection research: [ASVspoof 5 evaluation (arXiv)](https://arxiv.org/abs/2601.03944v1) · [Deepfake-Eval-2024](https://arxiv.org/html/2503.02857v4)
- ACMA: [Caller ID scams](https://www.acma.gov.au/caller-id-scams)
- Case report: [Ferrari (Fortune)](https://fortune.com/2024/07/27/ferrari-deepfake-attempt-scammer-security-question-ceo-benedetto-vigna-cybersecurity-ai)
- Microsoft Learn: [join operator (KQL)](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- MITRE ATT&CK: [T1566.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)

> *Drafting note: when this entry was written the publishers' sites could not be
> opened directly, so the figures above come from search-result summaries of these
> pages. Re-check the numbers against the originals before relying on them.*

⬅️ [Learning log index](README.md) · ➡️ Day 03: Why people and deepfake detectors both miss fakes (5 Nov)
