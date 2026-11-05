# Day 03 — Why People and Deepfake Detectors Both Miss Fakes

📅 5 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Days 01 and 02 ended on the same line: you can't judge the media, so judge the
request. The obvious objection is "fine, but surely a trained person or a good
detector can tell?" Plenty of vendors, and plenty of security awareness slides,
say yes.

The published evidence says: not reliably, and not in the way you'd hope. People
score close to chance on average, and are confident anyway. Detectors score well
on the benchmarks they were built on and noticeably worse on fakes found in the
wild. Both are still worth using, but only in the right role. This entry is about
what that role is, and about one specific failure that shows up in logs: a
"looks real" verdict being used to skip the control that would have caught the fraud.

---

## The concept

### How well do people do?

| Source | What it found | How far to trust it |
|---|---|---|
| **Diel et al., 2024** (*Computers in Human Behavior Reports*): a systematic review and meta-analysis | Pooled across **56 papers and 86,155 participants**, overall accuracy was about **55.5%**, with a confidence interval (roughly 49% to 62%) that includes 50%. By type: audio about 62%, video about 57%, images about 53%, text about 52%. Feedback training, AI support and "caricaturisation" lifted accuracy to about 65% in the subset of studies that tried them | The strongest evidence here, because it pools many studies. The audio figure rests on few studies, and lab tasks differ from a busy Tuesday call |
| **Mai et al., 2023** (UCL, *PLOS ONE*) | **529** participants identified machine-generated speech about **73%** of the time, in both English and Mandarin. Training helped only a little. The authors concluded detection by humans is unreliable | Single study. The authors cautioned that the synthesis was from relatively old algorithms, so newer fakes may be harder |
| **iProov, 2025** (vendor research) | In a test of **2,000** UK and US consumers primed to look for fakes, only **0.1%** correctly classified every real and fake item. Participants were also reported to be over-confident in their ability | Labelled vendor research: iProov sells biometric verification, so the finding suits its products. I found no independent replication |

Two honest readings. The first: people do better than a coin flip on some audio,
so "humans are useless" overstates it. The second: even the good numbers mean
roughly **one in four** fakes sails through for a listener who knows a test is
under way. A finance officer taking an unexpected call isn't primed, isn't
listening on good headphones and wants to help.

> 💡 **Confidence is the dangerous part.** A person who is 60% accurate and sure of
> themselves will wave the payment through. Don't build a process that asks
> staff to *feel* whether something is real.

### How well do detectors do?

A detector is a model that outputs a score for "how likely is this synthetic".
Three things make it weaker in the field than on the page.

| Problem | What it means | Evidence or judgement |
|---|---|---|
| **Benchmarks age** | A detector trained on older generators meets newer ones it has never seen | The **Deepfake-Eval-2024** benchmark collected fakes that circulated in 2024 (about 45 hours of video, 56.5 hours of audio and 1,975 images, from 88 websites in 52 languages). Open-source detectors' AUC fell by about **50% for video, 48% for audio and 45% for images** compared with earlier benchmarks. Commercial detectors did better but, per the authors, did not yet match deepfake forensic analysts. Fine-tuning on realistic data helped, which supports the point that data freshness matters |
| **Real-world compression** | Phone codecs, video-call compression and re-uploads strip the fine detail a detector might use | Day 02 covered narrowband audio: ASVspoof 5 found it among the hardest conditions. A voicemail left via a phone network is the worst case |
| **An adaptive attacker** | If an attacker can test fakes against a detector, they can iterate until it passes | My judgement, consistent with the adaptive-attack results for LLM guardrails that Day 15 covers. Public detectors are easy to query, so assume a determined fraudster has tried |

There's also a plain base-rate problem, which Day 21 develops. Most calls and
recordings your staff handle are genuine. A detector that is wrong 5% of the time
on genuine media creates a steady drip of false alarms, and people learn to ignore
it. One that is wrong 5% of the time on fakes lets the dangerous 1-in-1,000 case through.

### So where do people and detectors fit?

| | Good for | Bad for |
|---|---|---|
| **A person's instinct** | Noticing a wrong channel, odd urgency or a request that breaks process. Raising a hand | Judging whether a voice or face is synthetic |
| **A detector score** | A *tripwire*: a high "fake" score should pause a payment and trigger escalation | A *clearance*: a low score must never replace a call-back |
| **A process control** | Everything that moves money | Nothing; it's the control |

That asymmetry is the rule from ANALYSIS.md, applied: **let detection raise
suspicion, never lower it.** The failure to log for is the reverse case.

---

## Sample logs

All times are UTC on **Wednesday 4 November 2026**. Sydney is UTC+11, so 02:15 UTC
is **13:15 in Sydney**. All data is fictional. `NorthwindMediaCheck_CL` is a
**fictional custom table** for a deepfake-detector tool Northwind runs on request,
and `NorthwindPayments_CL` is the Day 02 table with an extra `CallbackStatus`
column. Real column names depend on your tools, and custom Sentinel columns often
carry type suffixes such as `_s` or `_d`, which I've left off. `Score` is the
detector's probability that the media is synthetic (0 to 1).

**Media checks** (`NorthwindMediaCheck_CL`, 5 rows):

```
TimeGenerated (UTC)  CheckId  RequestedBy                        MediaType  Source               Score  Verdict       PaymentId
2026-11-04 02:15:10  M-501    priya.nair@northwind-example.com   Audio      Voicemail (8 kHz)    0.12   Likely real   PAY-3401
2026-11-04 02:40:55  M-502    ben.okafor@northwind-example.com   Video      Teams recording      0.55   Inconclusive  PAY-3402
2026-11-04 03:05:20  M-503    priya.nair@northwind-example.com   Audio      WhatsApp voice note  0.91   Likely fake   PAY-3403
2026-11-04 03:30:00  M-504    ben.okafor@northwind-example.com   Video      Teams recording      0.08   Likely real   PAY-3404
2026-11-04 03:41:30  M-505    priya.nair@northwind-example.com   Audio      Voicemail (8 kHz)    0.15   Likely real   PAY-3405
```

**Payments** (`NorthwindPayments_CL`, 6 rows):

```
PaymentId  Approver                          Beneficiary          AmountAUD  BankAccountAgeDays  CallbackStatus  ApprovalTime (UTC)   FinalStatus
PAY-3401   sara.lund@northwind-example.com   Coastal Packaging    96000      0                   Skipped         2026-11-04 02:48:30  Released
PAY-3402   david.cho@northwind-example.com   Redgum Supplies      58000      2                   Completed       2026-11-04 03:20:05  Released
PAY-3403   sara.lund@northwind-example.com   Lakeside Consulting  130000     0                   Skipped         (none)               Rejected
PAY-3404   david.cho@northwind-example.com   Harbour Freight      64000      1                   Completed       2026-11-04 03:52:10  Released
PAY-3405   sara.lund@northwind-example.com   Green Valley Print   8200       40                  Skipped         2026-11-04 03:55:00  Released
PAY-3406   david.cho@northwind-example.com   Ironbark Hardware    77000      0                   Skipped         2026-11-04 04:10:00  Released
```

What was later found out (fictional): Coastal Packaging's real finance contact
denied sending the voicemail behind PAY-3401. It was synthetic, and the payment
was recalled. The Teams recordings (M-502, M-504) and the voicemail behind
PAY-3405 were genuine. The WhatsApp voice note behind PAY-3403 was synthetic.
PAY-3406 had no detector check at all.

---

## What to look for

1. **The detector scorecard.** Using the "later found out" facts: of the **2**
   synthetic items, the tool flagged **1** (M-503, score 0.91) and called the other
   "Likely real" (M-501, score 0.12). Of the **3** genuine items, it called **2**
   "Likely real" and **1** "Inconclusive". Five rows is far too few to measure a
   detector. This is an illustration of a miss, not an accuracy figure.
2. **Where the miss happened.** M-501 was an **8 kHz voicemail**, the worst case
   from the concept section. Nothing in the log proves the codec caused the miss,
   but it's the kind of source where you'd expect weaker results.
3. **A clean verdict, then money.** PAY-3401 (**AUD 96,000**, account age **0**
   days) was approved **33 min 20 s** after the "Likely real" check, with
   `CallbackStatus = Skipped`. That's the pattern this entry is about: the
   verdict looks like it stood in for the call-back.
4. **A clean verdict that is fine.** PAY-3404 also had "Likely real" and is large,
   but the call-back was **Completed**. The detector was an extra, not a substitute.
5. **An inconclusive verdict handled properly.** M-502 scored 0.55. The call-back
   on PAY-3402 was **Completed** and the money moved afterwards. That's what a
   middle score should trigger.
6. **A fake score that worked as a tripwire.** M-503 scored 0.91 and PAY-3403
   (AUD 130,000) was **Rejected**. Even so, the call-back was `Skipped`, so nobody
   confirmed anything with the real vendor. The score alone made the decision.
7. **Small and skipped.** PAY-3405 (**AUD 8,200**) was also approved with a
   skipped call-back after a "Likely real" verdict. Whether small payments need a
   call-back is a policy question, not a detection one, so the rule leaves it out.
8. **What the rule can't see.** PAY-3406 (**AUD 77,000**, new account,
   call-back skipped) had **no media check at all**, so a rule based on checks
   never sees it. A skipped call-back on a large new-account payment deserves its
   own alert, whether or not anyone ran a detector.

---

## Detection logic

**In plain English:** alert when a payment of **AUD 50,000 or more** is
**released** without a completed call-back, and a detector returned **"Likely real"**
for media linked to that payment within the **2 hours before** approval. Detector
checks are normal and skipped call-backs happen. The combination says someone
treated the verdict as permission.

**KQL (Microsoft Sentinel, fictional custom tables):**

```kql
// Large payment released without a call-back after a "Likely real" detector verdict
let minAmount = 50000;
let window = 2h;
let CleanChecks =
    NorthwindMediaCheck_CL
    | where TimeGenerated > ago(2d)
    | where Verdict == "Likely real"
    | project CheckTime = TimeGenerated, CheckId, MediaType, Source, Score, PaymentId;
NorthwindPayments_CL
| where ApprovalTime > ago(2d)
| where FinalStatus == "Released"
| where AmountAUD >= minAmount
| where CallbackStatus != "Completed"
| join kind=inner CleanChecks on PaymentId
| where ApprovalTime between (CheckTime .. (CheckTime + window))
| project PaymentId, Approver, Beneficiary, AmountAUD, BankAccountAgeDays,
          CallbackStatus, CheckId, Source, Score, CheckTime, ApprovalTime
```

I ran the same logic over the sample rows in Python. It returns **1** row:

```
PaymentId  Approver   Beneficiary        AmountAUD  CheckId  Score  CheckTime            ApprovalTime         Gap
PAY-3401   sara.lund  Coastal Packaging  96000      M-501    0.12   2026-11-04 02:15:10  2026-11-04 02:48:30  33 min 20 s
```

Why everything else drops out:

- **PAY-3402** and **PAY-3404** are dropped by `CallbackStatus != "Completed"`.
  PAY-3402's verdict was also "Inconclusive".
- **PAY-3403** is dropped by `FinalStatus == "Released"`: it was rejected.
- **PAY-3405** is dropped by the amount test (AUD 8,200).
- **PAY-3406** passes every payment test but has no check to join to, so
  `kind=inner` drops it. That's the gap from point 8.

**Tuning note:** the AUD 50,000 amount and 2-hour window are starting points, not
measured values. `Verdict` strings depend on the product, so map your tool's
categories deliberately, and decide whether "Inconclusive" with a skipped
call-back should also alert (I'd lean towards yes, as a lower severity). The
stronger fix is not a better rule but a workflow where **the payment can't be released
until `CallbackStatus` is Completed**, so the alert is a backstop. Add a second,
broader rule for "large, new account, call-back skipped" regardless of any
detector, since that is the one PAY-3406 would trigger. Finally, log detector
results for *every* check so you can measure its real hit and miss rates over time.

---

## Your turn

1. In your own words, why is "this detector said it's real" a more dangerous
   output than "this detector said it's fake"? Which one should change what a
   person does, and which should not?
2. Look at the three evidence rows in the people table. Rank them from most to
   least trustworthy for a policy decision, and say why. How does the iProov row
   differ from the other two?
3. In the sample, PAY-3403 was correctly rejected after a 0.91 score, but the
   call-back was skipped. Why is that still a process failure? What would you
   want the log to show instead?
4. Sketch a one-paragraph rule for staff: when may they use a detector, and what
   must they never use it for? Write it so a busy finance officer would follow it.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Diel et al.: [Human performance in detecting deepfakes: A systematic review and meta-analysis of 56 papers](https://doi.org/10.1016/j.chbr.2024.100538) (*Computers in Human Behavior Reports*, 2024; DOI as returned by search)
- Mai et al.: [Warning: Humans cannot reliably detect speech deepfakes](https://arxiv.org/pdf/2301.07829) (*PLOS ONE*, 2023; arXiv version)
- Chandra et al.: [Deepfake-Eval-2024](https://arxiv.org/abs/2503.02857) (arXiv; also linked from ANALYSIS.md)
- Vendor research: [iProov deepfake blindspot study, via Business Wire](https://www.businesswire.com/news/home/20250211131029/en) (vendor research, February 2025)
- Hashmi et al.: [Unmasking Illusions: Understanding Human Perception of Audiovisual Deepfakes](https://arxiv.org/html/2405.04097v2) (arXiv; humans above chance but behind the best automated detectors)
- Microsoft Learn: [join operator (KQL)](https://learn.microsoft.com/en-us/kusto/query/join-operator)
- MITRE ATT&CK: [T1566.004 Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)

> *Drafting note: when this entry was written, the publishers' sites could not be
> opened directly from the drafting environment, so the figures above come from
> search-result summaries of these pages. Re-check the numbers against the
> originals before relying on them.*

⬅️ [Learning log index](README.md) · ➡️ Day 04: Payment controls that stop BEC: call-backs and dual approval (6 Nov)
