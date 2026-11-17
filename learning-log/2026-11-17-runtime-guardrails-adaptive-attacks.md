# Day 15 — Runtime Guardrails and How Adaptive Attacks Beat Them

📅 17 November 2026 · 🏷️LLM security · ⏱️ ~30 min

---

## Why it matters

Days 11 to 14 used a prompt-attack classifier as one control among several,
and every entry said the same thing about it: useful telemetry, not a
boundary. Day 14's sanitiser couldn't decide whether a sentence was an
instruction, so the obvious next move is to put a model there that tries to
decide. That's what a runtime guardrail is.

Guardrails are worth having. The trouble is how their numbers are measured. A
guardrail is usually tested against a fixed set of known attacks, and a real
attacker doesn't stay inside that set. They try something, see whether it got
through, change it and try again. [ANALYSIS.md](../ANALYSIS.md#a-pragmatic-architecture)
puts guardrails at Layer 5, "telemetry first". Today is about why the
published research supports that, and about the one thing an adaptive
attacker can't avoid: a trail of failed attempts in your logs.

---

## The concept

### What a runtime guardrail is

A runtime guardrail is a check that runs on live traffic, alongside the main
model. [MITRE ATLAS AML.M0020 Generative AI Guardrails](https://atlas.mitre.org/mitigations/AML.M0020)
describes them as controls placed "between users, tools, and generative AI
models" that evaluate prompts, retrieved context, outputs and agent actions
"before they are accepted, executed, or shown to a user". The
[OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
(section "Model-Based Guardrails") names three placements:

| Placement | What it checks | What it's good at | What it misses |
|---|---|---|---|
| **Input screening** | User prompts and retrieved content, before the main model reads them | Known jailbreak and injection styles, copied attack text | A plainly worded request specific to your app (Day 11's "the team lead approved it") |
| **Output screening** | The model's reply, before it reaches the user or the next tool | Leaked system prompts, exfiltration markup, policy-breaking text | Anything that looks like a normal answer. This is Day 16's topic |
| **Action screening** | A proposed tool call, compared against what the user asked for | Tool calls that don't match the task | OWASP warns this "does not guarantee rejection of injected actions", so tool permissions still have to be enforced separately |

Most input guardrails are small classifiers. The
[Attacker Moves Second](https://arxiv.org/html/2510.09023v1) paper describes
the open ones it tested as following "the same recipe: a fine-tuned
BERT-based classifier trained on mixtures of benign prompts and known
jailbreak or injection triggers". Two vendor examples, from their own
documentation:

| Product | What it returns | Limits the vendor states |
|---|---|---|
| [Microsoft Prompt Shields](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection) | `detected` and `filtered` (true or false) for user prompt attacks and document attacks. Can block, or annotate and let the app decide | "Primarily trained and evaluated on English content". Doesn't judge whether content is harmful, accurate or "aligned with the application's task" |
| [Meta Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (open weights) | `benign` or `malicious` | 512-token window, so longer input has to be split and scanned in segments. Lists "Vulnerability to Adaptive Attacks" as a limitation, and says fine-tuning on your own application's data improves detection |

Meta also dropped the separate "injection" label from Prompt Guard 1 because
the objective was "too broad to be useful". That's the Day 11 problem in one
line: an instruction hidden in data is hard to tell apart from ordinary
text that happens to contain an instruction.

### Static numbers versus an attacker who adapts

A **static evaluation** runs a guardrail against a fixed dataset of known
attacks and reports the share that got through. An **adaptive attack** is
built against that particular defence: the attacker changes the input based on
what happened last time.
[The Attacker Moves Second](https://arxiv.org/html/2510.09023v1) (Nasr et
al., October 2025) tested 12 published defences this way. The 14 authors
are from Google DeepMind, OpenAI, Anthropic, ETH Zürich, HackAPrompt and
others, so this is partly vendor research. One of the defences it broke,
Model Armor, is a Google product. A selection of their results:

| Defence | Type | Reported before | Adaptive attack |
|---|---|---|---|
| Spotlighting (Day 14) | Prompting | Attack success as low as 1% | Above 95% (search) |
| Prompt sandwiching | Prompting | As low as 1% | Above 95% (search) |
| MetaSecAlign | Model trained against attacks | 2% on the AgentDojo benchmark | 96% (search) |
| Protect AI detector, PromptGuard, Model Armor | Guardrail classifiers | Near zero | Above 90% (search) |
| PIGuard | Guardrail classifier | Near zero | 71% (search) |

They used four kinds of attack: gradient-based (needs the model's weights),
reinforcement learning, a search method in which one LLM rewrites the
attack and keeps the best variants, and a human red-teaming competition with
more than 500 participants and US$20,000 in prizes. The humans succeeded
too, with 265 successful attacks against spotlighting alone. The paper's first lesson is "Small static evals can be
misleading!"

One detail matters for defenders. The search attack against the classifiers
ran with "the detector's confidence score and detection flag fed back to the
attacker", and was given up to 800 queries. The attacker learns from each
blocked attempt, and that's how a guardrail gets beaten. It's also what
shows up in your logs.

### Cheap evasion: characters the guardrail and the model read differently

Adaptive search isn't always needed.
[Hackett et al.](https://arxiv.org/abs/2504.11168) (LLMSEC 2025 workshop)
tested six guardrails, including Azure Prompt Shield, Meta Prompt Guard and
NVIDIA NeMo Guard, against 12 character tricks: zero-width characters,
homoglyphs, bidirectional text, Unicode tags and emoji smuggling among them.
Emoji smuggling reached 100% evasion. Against Azure Prompt Shield, character
tricks averaged 71.98% evasion for prompt injections and 60.15% for
jailbreaks. Their explanation is that the guardrail and the main LLM were
trained differently, so text can be unreadable to one and still "fully
comprehensible" to the other. They disclosed to vendors between February 2024
and April 2025, so current versions may do better. Treat the figures as
showing the type of weakness, not as today's numbers.

That's where Day 14 fits. Strip tag characters, zero-width characters and
bidi overrides *before* the classifier sees the text, and a whole family of
these tricks stops working. The sanitiser and the guardrail work better
together than either does alone.

### Retries are cheap

[Best-of-N Jailbreaking](https://arxiv.org/abs/2412.03556) (Hughes et al.,
December 2024) didn't optimise anything. It sent random variations of a
prompt (shuffled letters, random capitals) until one worked, and reached 89%
on GPT-4o and 78% on Claude 3.5 Sonnet with 10,000 samples. Success grew
steadily with the number of attempts. The OWASP cheat sheet's response is
that rate limiting "restricts attempt budgets; it does not establish model
robustness". In other words, a rate limit raises the price of an attack. It
doesn't make the guardrail stronger.

### What this means in practice

None of this means you should turn guardrails off. They stop copy-and-paste
attacks cheaply, and copy-and-paste attacks are most of the traffic. The
mistake is putting one where a deterministic control should be. These are
my working rules, which are judgement rather than published guidance:

| Decision | Trade-off |
|---|---|
| **Keep scores and guardrail names out of user-facing messages** | Nasr et al.'s search used the score as its guide. Hiding it only slows an attacker down, because pass or block is still visible from how the app behaves. A plain "I can't help with that" is enough for the user |
| **Give each client a budget of blocked attempts** | Raises the cost of best-of-N and search attacks. Customers behind one carrier or office IP share the budget, so set it per signed-in user where you can |
| **Decide what happens when the guardrail fails** | Fail-closed means a classifier outage takes the chatbot down. Fail-open means attacks pass unscreened during the outage. Either is defensible if it's written down, logged and alerted on |
| **Choose a guardrail that differs from the main model** | OWASP: the same jailbreak "is more likely to defeat a guardrail that shares its training and prompt format" |
| **Test it yourself with adaptive attacks** | A vendor's benchmark tells you about static attacks only. A regular red-team run that iterates (Day 11's `svc-llm-redteam`) tells you more |
| **Watch the guardrail's own statistics** | OWASP: "Sudden changes in the approval rate, or in the distribution of refusal reasons, often precede a working bypass" |

The last row leads into today's detection. An adaptive attacker has to fail
before succeeding, and each failure is a logged block.

### Northwind's order-help chat

In October Northwind launched **Order Help**, a chat widget on its public
website. Customers aren't signed in. It has two tools: `lookup_order` (needs
the order number plus the matching email or postcode) and `create_return`
(same check, and only for orders delivered within 30 days). Because it's
public and unauthenticated, Northwind put an open-weight prompt-attack
classifier in front of it in **block** mode, following Day 11's reasoning,
with a threshold of 0.80. The guardrail is set to fail open after a
two-second timeout. All fictional.

During today's review, the AI platform team noticed the widget's block message
reads "Message blocked by safety filter (confidence 0.97)". That's the score,
handed straight to whoever is typing.

---

## Sample logs

All times are UTC (21:00 UTC on 16 November is 08:00 on 17 November in
Sydney). Everything is fictional.

Order Help writes one row per check to a **fictional custom table**
`NorthwindGuardrail_CL`. `Stage` is `input` (classifier on the customer's
message), `action` (tool permission check) or `output` (check on the reply).
`Score` is the classifier's score, and anything at 0.80 or above is blocked.
`Verdict` is `pass`, `block`, `allow`, `deny` or `error`. `Detail` is
written by the logging layer and describes the message instead of quoting it.
`ClientId` is a browser cookie. This extract has 29 rows from 8 sessions,
7 client IDs and 6 IP addresses:

```
TimeGenerated        SessionId  ClientId  ClientIP        Stage   Check          Score  Verdict  Tool           Detail
2026-11-16 21:02:10  W-901      C-7731    203.0.113.45    input   prompt_guard   0.99   block    -              role-play: asks the bot to act as "returns manager" and issue a label for order 90114
2026-11-16 21:04:40  W-901      C-7731    203.0.113.45    input   prompt_guard   0.98   block    -              same goal, written as a fake "system notice"
2026-11-16 21:07:05  W-901      C-7731    203.0.113.45    input   prompt_guard   0.96   block    -              same goal, written as a supplier memo
2026-11-16 21:11:30  W-902      C-7731    203.0.113.45    input   prompt_guard   0.93   block    -              same goal, polite complaint quoting a made-up returns "policy"
2026-11-16 21:15:50  W-902      C-7731    203.0.113.45    input   prompt_guard   0.88   block    -              same text, "policy" quote shortened
2026-11-16 21:19:20  W-902      C-7731    203.0.113.45    input   prompt_guard   0.84   block    -              same text, "policy" moved to the end
2026-11-16 21:24:00  W-903      C-7744    203.0.113.45    input   prompt_guard   0.81   block    -              same text, new browser session (cookie cleared)
2026-11-16 21:27:35  W-903      C-7744    203.0.113.45    input   prompt_guard   0.74   pass     -              same goal, "policy" buried in a long story about a late delivery
2026-11-16 21:27:36  W-903      C-7744    203.0.113.45    action  tool_policy    -      deny     create_return  order 90114: postcode not supplied or not matched
2026-11-16 21:29:10  W-903      C-7744    203.0.113.45    input   prompt_guard   0.71   pass     -              same story, asks the bot to look up order 90114 "to confirm the postcode"
2026-11-16 21:29:11  W-903      C-7744    203.0.113.45    action  tool_policy    -      deny     lookup_order   order 90114: needs matching email or postcode
2026-11-16 21:29:12  W-903      C-7744    203.0.113.45    output  output_policy  -      pass     -              "I can't open that order without the email or postcode on it"
2026-11-16 21:40:00  W-910      C-7802    198.51.100.20   input   prompt_guard   0.86   block    -              "Ignore my last message, wrong order number. It's 90377"
2026-11-16 21:41:15  W-910      C-7802    198.51.100.20   input   prompt_guard   0.82   block    -              "Please disregard what I said before, the order is 90377"
2026-11-16 21:42:30  W-910      C-7802    198.51.100.20   input   prompt_guard   0.12   pass     -              "Order 90377, postcode 2000, where is it?"
2026-11-16 21:42:31  W-910      C-7802    198.51.100.20   action  tool_policy    -      allow    lookup_order   order 90377, postcode matched
2026-11-16 22:05:00  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              well-known "no rules" persona text, copied verbatim
2026-11-16 22:05:20  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              same text
2026-11-16 22:05:40  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              same text
2026-11-16 22:06:00  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              same text
2026-11-16 22:06:20  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              same text
2026-11-16 22:06:40  W-920      C-7810    192.0.2.77      input   prompt_guard   0.99   block    -              same text, then the session stops
2026-11-16 22:20:00  W-930      C-7815    198.51.100.61   input   prompt_guard   0.03   pass     -              "Can I return a jacket I bought on sale?"
2026-11-16 22:20:02  W-930      C-7815    198.51.100.61   output  output_policy  -      pass     -              returns policy summary
2026-11-16 22:35:00  W-940      C-7820    203.0.113.90    input   prompt_guard   -      error    -              classifier timed out after 2 s, prompt forwarded unscreened (fail-open)
2026-11-16 22:35:04  W-940      C-7820    203.0.113.90    action  tool_policy    -      allow    lookup_order   order 90388, email matched
2026-11-16 22:50:00  W-950      C-7833    198.51.100.140  input   prompt_guard   0.05   pass     -              "When will order 90412 arrive? Postcode 3000"
2026-11-16 22:50:01  W-950      C-7833    198.51.100.140  action  tool_policy    -      allow    lookup_order   order 90412, postcode matched
2026-11-16 22:50:03  W-950      C-7833    198.51.100.140  output  output_policy  -      block    -              reply contained a phone number not on the order, replaced with a generic message
```

Context (fictional): order 90114 belongs to a real Northwind customer who
didn't contact Order Help today. Postcodes 2000 and 3000 are the Sydney and
Melbourne CBDs, used here as ordinary values.

---

## What to look for

1. **Count first.** **29** rows: **21** input checks (**15** blocked,
   **5** passed, **1** error), **5** tool checks (**3** allowed, **2**
   denied) and **3** output checks (**2** passed, **1** blocked). **8**
   sessions, **7** client IDs, **6** IP addresses.
2. **203.0.113.45 is an adaptive attack, done by hand or by script.** Seven
   blocks in 22 minutes with the same goal each time (a return label for
   someone else's order) and a different wrapping each time. The score falls
   at every step: 0.99, 0.98, 0.96, 0.93, 0.88, 0.84, 0.81, then 0.74, which
   passed. That's the pattern Nasr et al. describe, and the widget's
   "confidence 0.97" message gave the attacker the score to steer by. The
   cookie changed from C-7731 to C-7744 at 21:24 while the IP stayed the same,
   so counting by `ClientId` alone would have split the attack in two.
3. **The guardrail lost, and the tool check held.** Once past the
   classifier, the attacker asked for `create_return` and then `lookup_order`
   on order 90114, and both were denied because no matching postcode was
   given. This is ANALYSIS.md's Layer 1 working as designed. The guardrail
   was beaten exactly as the research predicts, and it didn't matter because
   the deterministic check didn't depend on it. Next steps: remove the score
   from the block message, check whether `lookup_order` limits wrong
   postcode guesses per order, and tell the owner of order 90114 nothing yet,
   because no data came out.
4. **192.0.2.77 is commodity noise.** Six identical, copied attacks in 100
   seconds, all scoring 0.99, then nothing. The guardrail is doing its cheap
   job here. It's worth an entry in the daily review and a rate limit, but
   it's no threat to Order Help.
5. **198.51.100.20 is a false positive.** "Ignore my last message" and
   "disregard what I said before" are normal customer language and scored
   above the threshold. That's two blocks before the customer gave up on the
   wording and just asked. Day 11 saw the same thing with `m.ito`. Block mode
   puts that friction on paying customers.
6. **The other three.** 22:35 is a fail-open: the classifier timed out and
   the message went through unscreened. This one was harmless (the customer's
   own order, email matched), but nobody would have noticed if it hadn't been,
   so timeouts need their own count. 22:50 is an output-check block on an
   ordinary request, which is tomorrow's topic. 22:20 is an ordinary question.

---

## Detection logic

**In plain English:**

- For each **client IP** over a day, count the input messages the guardrail
  **blocked**.
- Anything with **5 or more** blocks is probing. Look at everything that IP
  did from its first block onwards.
- **High** if any of its messages later **passed** the guardrail, because
  the attacker has found a way through and only the controls behind the
  model are left. **Medium** if every message was blocked.
- Show the tool and output checks it hit after that, and the score trend
  (highest, lowest blocked, lowest passed), so the analyst can see at a
  glance whether the attacker was steering towards the threshold.

**KQL (Microsoft Sentinel / Log Analytics, over a fictional custom table):**

```kql
// Adaptive probing of a prompt-attack guardrail, by client IP
// NorthwindGuardrail_CL is a FICTIONAL custom table
let lookback = 1d;
let blockThreshold = 5;
let events = NorthwindGuardrail_CL
    | where TimeGenerated > ago(lookback);
let probers = events
    | where Stage == "input" and Verdict == "block"
    | summarize FirstBlock = min(TimeGenerated), Blocks = count() by ClientIP
    | where Blocks >= blockThreshold
    | project ClientIP, FirstBlock;
events
| join kind=inner probers on ClientIP
| where TimeGenerated >= FirstBlock
| summarize InputBlocks      = countif(Stage == "input" and Verdict == "block"),
            PassedAfterBlock = countif(Stage == "input" and Verdict == "pass"),
            ControlHits      = countif((Stage == "action" and Verdict == "deny")
                                    or (Stage == "output" and Verdict == "block")),
            DeniedTools      = make_set_if(Tool, Stage == "action" and Verdict == "deny"),
            TopScore         = max(Score),
            LowestBlocked    = minif(Score, Stage == "input" and Verdict == "block"),
            LowestPassed     = minif(Score, Stage == "input" and Verdict == "pass"),
            Sessions         = dcount(SessionId),
            Clients          = make_set(ClientId),
            FirstSeen        = min(TimeGenerated),
            LastSeen         = max(TimeGenerated)
    by ClientIP
| extend Severity = iff(PassedAfterBlock > 0, "High", "Medium")
| project FirstSeen, LastSeen, ClientIP, Severity, InputBlocks, PassedAfterBlock,
          ControlHits, DeniedTools, TopScore, LowestBlocked, LowestPassed,
          Sessions, Clients
```

On the sample, the query returns **2 rows**: `203.0.113.45` **High** and
`192.0.2.77` **Medium**. I ran the same logic in Python over the 29 rows, with
a check that every score of 0.80 or more is a block and every lower score a
pass:

```
rows 29 sessions 8 clientids 7 ips 6
stage Counter({'input': 21, 'action': 5, 'output': 3})
input verdicts Counter({'block': 15, 'pass': 5, 'error': 1})
action Counter({'allow': 3, 'deny': 2})
output Counter({'pass': 2, 'block': 1})
192.0.2.77 blocks 6 passedAfter 0 controlHits 0 sessions 1 clients ['C-7810'] topScore 0.99 lowestBlocked 0.99 lowestPass None first 2026-11-16 22:05:00 last 2026-11-16 22:06:40 Medium
198.51.100.140 blocks 0 -> no alert
198.51.100.20 blocks 2 -> no alert
198.51.100.61 blocks 0 -> no alert
203.0.113.45 blocks 7 passedAfter 2 controlHits 2 sessions 3 clients ['C-7731', 'C-7744'] topScore 0.99 lowestBlocked 0.81 lowestPass 0.71 first 2026-11-16 21:02:10 last 2026-11-16 21:29:12 High
203.0.113.90 blocks 0 -> no alert
```

What it excludes: `198.51.100.20` (2 blocks, under the threshold, the false
positive customer), `198.51.100.140` (an output block with no input blocks
in front of it), and `198.51.100.61` and `203.0.113.90` (no blocks). The
fail-open at 22:35 isn't covered by this rule at all. It needs a separate
count of `Verdict == "error"` per hour, alerting when timeouts rise, because
a guardrail that's down looks exactly like a guardrail that's passing
everything.

**What I verified and what I didn't.** The table, its columns, the widget and
the threshold are invented. `join kind=inner`, `countif`, `minif`,
`make_set_if`, `dcount` and `iff` are standard KQL. After the join, the right
side's copy of `ClientIP` is renamed (to `ClientIP1`), so the `summarize ... by
ClientIP` uses the left side's column. As in Day 14, if the table were created
with the older HTTP Data Collector API the columns would carry type suffixes
such as `Score_d` and `ClientIP_s`. The query has only been run as the Python
equivalent, not against a live workspace. If you use Prompt Shields instead
of a scoring classifier, you only get `detected` true or false, so drop the
score columns. The block and pass counts still work.

**Tuning note:** 5 blocks in a day is my starting point, not a published
figure. It sits above the false-positive customer here (2) and well below
the 800 queries Nasr et al. allowed their search attack. Grouping by IP
catches the cookie reset in this sample, but it merges unrelated customers
behind one carrier-grade NAT or office proxy and misses an attacker who
rotates IPs. If Order Help ever gets sign-in, group by account instead. Expect
the Medium rows to be mostly copied jailbreaks like 192.0.2.77. Send those to
a daily review rather than paging anyone, and keep paging for High. The
rule's real blind spot is an attacker who gets through on the first or second
try, which the character tricks in Hackett et al. can do. For that case there
is no trail of failures, only the tool and output checks behind the model,
which is why those checks matter more than the guardrail.

---

## Your turn

1. Rewrite Order Help's block message so it helps a genuine customer like
   `198.51.100.20` without giving an attacker the score. Then explain, using
   Nasr et al., why this slows the 203.0.113.45 attack down but doesn't stop
   it.
2. The product owner wants to switch the guardrail to fail-closed after
   seeing the 22:35 row. Write the two-line case for each option, and say
   which you'd choose for Order Help and which for Ask Northwind's
   `issue_refund` path.
3. A vendor offers a guardrail with "99.8% detection on a public jailbreak
   benchmark". Write three questions you'd ask before buying it, using what
   you learned about static and adaptive evaluation.
4. Suppose the attacker at 203.0.113.45 had guessed the postcode on their
   second try. Using Day 13's Rule of Two, list which controls would still
   stand between them and a return label, and what you'd add.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Nasr et al.: [The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections](https://arxiv.org/html/2510.09023v1) (12 defences, four attack types, the four lessons)
- Hackett et al.: [Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks against Prompt Injection and Jailbreak Detection Systems](https://arxiv.org/abs/2504.11168) (LLMSEC 2025, character injection against six guardrails)
- Hughes et al.: [Best-of-N Jailbreaking](https://arxiv.org/abs/2412.03556) (random variations and the attempt budget)
- OWASP Cheat Sheet Series: [LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) (see "Model-Based Guardrails" and "Best-of-N Attack Mitigation")
- Microsoft Learn: [Prompt Shields in Azure AI Content Safety](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/concepts/jailbreak-detection) (vendor docs: block versus annotate, stated limits)
- Meta: [Llama Prompt Guard 2 model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) (vendor docs: labels, 512-token window, limitations)
- MITRE ATLAS: [AML.T0054 LLM Jailbreak](https://atlas.mitre.org/techniques/AML.T0054) · [AML.M0020 Generative AI Guardrails](https://atlas.mitre.org/mitigations/AML.M0020)
- NCSC: [Prompt injection is not SQL injection (it may be worse)](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)
- This log: [ANALYSIS.md, Layer 5](../ANALYSIS.md#a-pragmatic-architecture) (probabilistic guardrails, telemetry first) · [Day 11](2026-11-13-direct-prompt-injection-vs-jailbreaking.md) (block versus annotate, the false positive on "ignore the earlier ticket") · [Day 13](2026-11-15-threat-modelling-agents-trifecta-rule-of-two.md) (Rule of Two) · [Day 14](2026-11-16-input-handling-sanitisation-limits.md) (sanitising before the classifier)

⬅️ [Learning log index](README.md) · ➡️ [Day 16: Output validation and data exfiltration channels (18 Nov)](2026-11-18-output-validation-exfiltration-channels.md)
