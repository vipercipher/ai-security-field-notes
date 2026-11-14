# Day 13 — Threat Modelling Agents: Lethal Trifecta and Rule of Two

📅 15 November 2026 · 🏷️LLM security · ⏱️ ~30 min

---

## Why it matters

Days 10 to 12 showed what happens when a model reads something an outsider
wrote. Day 11 ended with the classifier as telemetry, not a boundary, and
Day 12 showed EchoLeak walking past a classifier, a link filter and a content
security policy one after another. So if you can't reliably stop the
injection, the useful question becomes: **when the model is fooled, what can
it actually do?**

That's a threat-modelling question, and it can be answered before an agent
ships, from a list of its tools. Two short models do most of the work.
[ANALYSIS.md](../ANALYSIS.md#start-with-blast-radius) says to run them on
every agent before buying a single guardrail. Today is about how to do that
properly, where the models disagree, and how the SOC can check that an
agent's real behaviour still matches the threat model someone wrote for it.

---

## The concept

### Two models, one idea

| | **Lethal trifecta** | **Agents Rule of Two** |
|---|---|---|
| **Who** | [Simon Willison, June 2025](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) | [Meta, October 2025](https://ai.meta.com/blog/practical-ai-agent-security/) |
| **The three properties** | Access to private data · exposure to untrusted content · the ability to communicate externally | **[A]** process untrustworthy inputs · **[B]** access sensitive systems or private data · **[C]** change state or communicate externally |
| **The rule** | If an agent has all three, an attacker can trick it into sending your data to them. Avoid the combination | Within a session, an agent should satisfy no more than two. If it needs all three, it shouldn't run autonomously and needs at least human-in-the-loop approval "or another reliable means of validation" |
| **What it covers** | Data theft | Data theft *and* harmful actions, because [C] includes changing state |
| **Where it came from** | Willison's years of writing up exfiltration bugs in production assistants | Willison's trifecta plus the [Chromium Rule of 2](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md) (pick no more than two of untrustworthy input, memory-unsafe language and high privilege) |

The Chromium origin is worth knowing because it explains the mindset. Chrome's
security team didn't wait for bug-free C++ before shipping a parser. They
assumed bugs and made sure a bug could only land somewhere with little to
lose. The agent version assumes the injection lands and limits what the agent
can reach once it has.

### Where they differ, and the caveats the authors added

- **State change.** Willison [wrote](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
  that the trifecta's one gap is that it only covers exfiltration, and that
  Rule of Two fixes that by adding "change state". A refund, a deleted file or
  a pipeline run does harm without any data leaving.
- **[A] + [C] isn't safe.** In the same post, Willison added an update: an
  agent with untrusted input and the ability to change state can still do
  harm without touching anything sensitive. Meta responded by relabelling the
  two-leg overlaps from "safe" to **"lower risk"**, and Meta's Mick Ayzenberg
  clarified that [B] means *any* sensitive system, not only private data. An
  [AC] agent should be working somewhere that doesn't matter, such as a tight
  sandbox.
- **"Within a session."** The rule is about one context window. Meta's post
  says an agent can safely move between configurations, for example starting
  in [AC] to browse the web and then making a **one-way switch** that turns
  off communication before it touches internal systems. The thing to break is
  the chain [A] → [B] → [C].
- **What it doesn't cover.** Meta lists the limits plainly: it isn't a
  defence against hallucinations, excessive privilege, spam, agent mistakes,
  or lower-impact outcomes such as misinformation in an answer. It's "a
  supplement — and not a substitute" for least privilege, and designs that
  pass can still fail, for example when "a user blindly confirm[s] a warning
  interstitial".

### Scoring a tool is harder than it looks

Most of the work is deciding which legs each tool gives the agent. Real tools
rarely give only one.

| Tool or feature | Legs | Why |
|---|---|---|
| Read a customer ticket or a shared mailbox | **A + B** | Outsiders write the text, and it's also your customers' private data |
| Fetch a URL | **A + C** | The page can carry instructions, and the request itself can carry data out. Willison: if a tool can make an HTTP request, "to an API, or to load an image, or even providing a link for a user to click", it can be used to send stolen data back |
| Render Markdown images in the chat window | **C** | Day 12: the image fetch *was* the exit in EchoLeak |
| Send email, even internal-only | **C** | An allow-list narrows it, but it still communicates. Meta's own Email-Bot example includes "sending phishing messages to the target's friends" |
| Issue a refund, run a pipeline, update a record | **C** | State change, even with no data leaving |
| Read a curated internal knowledge base that only staff can edit | **None, or B** | Judgement call. If anyone can write to it, it becomes [A] (Day 18 covers this) |

That's how a "read-only" agent turns out to have all three legs. Willison's
point about MCP is the same one: plugging tools together from different
sources makes it easy to build the trifecta without noticing, and no vendor
can protect you from a combination you made yourself.

### Removing a leg: the options and what they cost

Meta's examples, mapped to what they cost you:

| Configuration | How you get there | Example from Meta | The cost |
|---|---|---|---|
| **[BC]**, drop A | Only process content from trusted authors (Meta calls this author lineage) | An internal coding agent that only reads code and data written by staff | Loses the most useful inputs: customer tickets, supplier email, the web |
| **[AC]**, drop B | Sandbox it with no session data, no SSO and nothing sensitive in reach | A web-browsing research assistant | Can't personalise or act on your systems. And [A]+[C] can still cause harm |
| **[AB]**, drop C | Human confirmation for actions, or destinations limited to trusted ones | A travel assistant that asks before booking and only visits URLs from trusted sources | Approval fatigue. A confirmation that people click without reading is no control at all |

The ATLAS mitigation [AML.M0030 Restrict AI Agent Tool Invocation on
Untrusted Data](https://atlas.mitre.org/mitigations/AML.M0030) is the
practical form of this: restrict or require confirmation for tool use once
untrusted data has entered the context, and always require confirmation for
high-consequence actions. I'll call that a **taint rule**: the session is
tainted from the first [A] onwards. It's the same principle as the NCSC
advice quoted in [ANALYSIS.md](../ANALYSIS.md#a-pragmatic-architecture),
that privileges should drop to those of whoever wrote the data being read.

### Northwind's agent register

After Day 12, Northwind's AI platform team started a threat model register:
one row per agent, listing its tools, the legs it's *meant* to have, and what
stops the chain. All fictional:

| Agent | Tools | Declared legs | What breaks the chain |
|---|---|---|---|
| `ask-northwind` (support assistant, Days 10 to 12) | `search_kb`, `get_order`, `get_ticket`, `search_support_mailbox`, `issue_refund` (up to A$200), `send_email` (internal allow-list) | **A B C** | Taint rule switched on 14 Nov: refunds need user confirmation after external content enters the session. Email is limited to `northwind-example.com` |
| `ap-inbox-assistant` (accounts payable) | `read_ap_mailbox`, `lookup_vendor`, `create_change_request` | **A B C** | It can't change bank details. It can only raise a change request, which goes through the Day 4 call-back process |
| `web-research` (marketing) | `fetch_url` | **A C** | Sandboxed browser, no Northwind sign-in, nothing internal in reach |
| `deploy-helper` (engineering) | `read_repo`, `run_pipeline` | **B C** | Reads only Northwind's own repositories, so no untrusted input |

Look at Ask Northwind honestly: it has had all three legs since Day 10,
because customer tickets were always external. The refund cap and email
allow-list limit the damage, but they don't validate each action, so on
Meta's terms it still needs the taint rule. Whether A$200 per refund is an
acceptable loss without approval is a business decision, not a security one.
My view is that it isn't, because an injected instruction can repeat it.

---

## Sample logs

All times are UTC (21:02 UTC on 14 November is 08:02 on 15 November in
Sydney). Everything is fictional. Times have seconds because order within a
session matters today.

Since Day 12, every Northwind agent's tool calls go through one gateway,
which logs them to a **fictional custom table** `NorthwindAgentGateway_CL`.
`Approval` is `human` if a person confirmed the call in the user interface
and `none` otherwise. The gateway doesn't know about legs. Those come from
the register above, joined in at query time. This extract has 23 rows from 9
sessions, 4 agents and 8 users:

```
TimeGenerated        SessionId  Agent               UserUpn    ToolName                Decision  Approval  Detail
2026-11-14 21:02:10  S-501      ask-northwind       m.ito      get_order               allowed   none      order 88210, in user's queue
2026-11-14 21:02:40  S-501      ask-northwind       m.ito      search_kb               allowed   none      returns article KB-087
2026-11-14 21:15:05  S-502      ask-northwind       h.nguyen   get_ticket              allowed   none      T-4533, customer portal (external)
2026-11-14 21:15:30  S-502      ask-northwind       h.nguyen   get_order               allowed   none      order 88231
2026-11-14 21:16:02  S-502      ask-northwind       h.nguyen   issue_refund            allowed   none      A$180, order 88231
2026-11-14 21:30:00  S-503      ask-northwind       p.dalton   search_support_mailbox  allowed   none      M-7790 from orders@fabrikam.example
2026-11-14 21:30:40  S-503      ask-northwind       p.dalton   get_order               allowed   none      order 88240
2026-11-14 21:31:15  S-503      ask-northwind       p.dalton   issue_refund            allowed   human     A$95, order 88240, user confirmed amount and order
2026-11-14 21:44:00  S-504      ask-northwind       r.kaur     issue_refund            allowed   none      A$60, order 88197 named by user
2026-11-14 21:45:10  S-504      ask-northwind       r.kaur     get_ticket              allowed   none      T-4529, customer portal (external)
2026-11-14 22:05:00  S-505      ask-northwind       c.brennan  search_support_mailbox  allowed   none      M-7795 from billing@contoso-supplies.example
2026-11-14 22:05:30  S-505      ask-northwind       c.brennan  send_email              denied    none      to=accounts@contoso-supplies.example (not on allow-list)
2026-11-14 22:20:00  S-506      ap-inbox-assistant  l.foster   read_ap_mailbox         allowed   none      invoice email from billing@fabrikam.example
2026-11-14 22:20:20  S-506      ap-inbox-assistant  l.foster   lookup_vendor           allowed   none      vendor V-1042
2026-11-14 22:21:00  S-506      ap-inbox-assistant  l.foster   create_change_request   allowed   human     bank details change for V-1042, queued for call-back
2026-11-14 22:40:00  S-507      web-research        j.marsh    fetch_url               allowed   none      www.fabrikam.example/products
2026-11-14 22:40:30  S-507      web-research        j.marsh    fetch_url               allowed   none      www.contoso.example/pricing
2026-11-14 22:41:00  S-507      web-research        j.marsh    fetch_url               allowed   none      docs.tailspin.example/specs
2026-11-14 23:00:00  S-508      deploy-helper       k.obrien   read_repo               allowed   none      northwind/web-shop
2026-11-14 23:00:40  S-508      deploy-helper       k.obrien   fetch_url               allowed   none      packages.example/widget-utils README
2026-11-14 23:01:30  S-508      deploy-helper       k.obrien   run_pipeline            allowed   none      web-shop to staging, build arguments changed
2026-11-14 23:20:00  S-509      deploy-helper       k.obrien   read_repo               allowed   none      northwind/warehouse-api
2026-11-14 23:20:50  S-509      deploy-helper       k.obrien   run_pipeline            allowed   none      warehouse-api to staging
```

Context (fictional): `l.foster` works in accounts payable, `j.marsh` is on
loan to marketing for the week, and `k.obrien` is a platform engineer. The
other users are the support agents from earlier days. Nobody has looked at
the content of T-4533 or the README in S-508 yet.

---

## What to look for

1. **Count first.** **23** rows, **9** sessions, **4** agents, **8** users.
   **22** calls allowed and **1** denied. **2** calls have human approval
   (S-503 and S-506). **11** calls carry the C leg once the register is
   joined in, and **6** sessions (S-502 to S-506 for the support and AP
   agents, plus S-508) touch all three legs.
2. **Touching all three legs isn't the finding.** What matters is *order*
   and *approval*: was there untrusted content in the context **before** an
   unapproved C action? Six sessions have all three legs, but only three
   meet that test.
3. **S-502: the taint rule has a hole.** An external ticket came in, then a
   A$180 refund went through with no confirmation. S-503 shows the taint rule
   working for `search_support_mailbox`, so the likely cause is that the rule
   was keyed on that *tool name* rather than on the A leg, and `get_ticket`
   wasn't on the list. That's a design gap, not proof of an attack. The refund
   may be completely legitimate, which is exactly what someone needs to check
   by reading T-4533.
4. **S-505: the deterministic control held.** External email in, then an
   attempt to email a `contoso-supplies.example` address, denied by the
   allow-list. Nothing left, but a model trying to write to an outside
   address straight after reading an outside email is worth a look. It's the
   same shape as Day 10's S-201.
5. **S-508: drift.** `deploy-helper` was registered as [BC]. Today it called
   `fetch_url`, which isn't in its declared tool list, read a public package
   README and then ran a pipeline with changed build arguments. Whoever added
   the tool gave it the A leg, and the register wasn't updated. This is the
   most serious row in the extract, because a pipeline run can change what
   ships.
6. **The noise.** S-504 issued a refund *before* reading the external
   ticket, so the ticket couldn't have driven it. S-503 and S-506 had all
   three legs with human approval on the action. S-507 is [AC] by design, and
   S-501 and S-509 never had A.

---

## Detection logic

**In plain English:**

- **Alert (per session):** a C-leg tool call with no human approval, where
  the same session had already made an A-leg call **earlier** and a B-leg
  call at or before that time. **High** if the call was allowed, **Medium**
  if it was denied. Legs come from the register, not from the agent's own
  description of what it was doing. A tool missing from the register is
  treated as having all three legs, so new tools fail loud.
- **Hunt (per agent, weekly):** legs actually used that aren't in the
  agent's declared profile. That's the register going out of date. It's a
  coarse version of AML.M0038 AI Agent Scope Drift Detection, which the
  [ATLAS page for AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
  lists as a mitigation: treat tool use inconsistent with the assigned task
  as a sign of drift.

**KQL (Microsoft Sentinel / Log Analytics, over a fictional custom table):**

```kql
// Agents Rule of Two: unapproved action after untrusted content, per session
// NorthwindAgentGateway_CL is a FICTIONAL custom table; the register is inline
let lookback = 1d;
let ToolRegister = datatable(ToolName:string, Legs:dynamic, Registered:bool) [
    "search_kb",              dynamic([]),          true,
    "get_order",              dynamic(["B"]),       true,
    "get_ticket",             dynamic(["A","B"]),   true,
    "search_support_mailbox", dynamic(["A","B"]),   true,
    "issue_refund",           dynamic(["C"]),       true,
    "send_email",             dynamic(["C"]),       true,
    "read_ap_mailbox",        dynamic(["A","B"]),   true,
    "lookup_vendor",          dynamic(["B"]),       true,
    "create_change_request",  dynamic(["C"]),       true,
    "fetch_url",              dynamic(["A","C"]),   true,
    "read_repo",              dynamic(["B"]),       true,
    "run_pipeline",           dynamic(["C"]),       true
];
let calls = NorthwindAgentGateway_CL
    | where TimeGenerated > ago(lookback)
    | lookup kind=leftouter ToolRegister on ToolName
    | extend Legs = iff(isnull(Registered), dynamic(["A","B","C"]), Legs);
let sessionLegs = calls
    | summarize FirstA = minif(TimeGenerated, set_has_element(Legs, "A")),
                FirstB = minif(TimeGenerated, set_has_element(Legs, "B"))
        by SessionId;
calls
| where set_has_element(Legs, "C") and Approval == "none"
| join kind=inner sessionLegs on SessionId
| where isnotnull(FirstA) and isnotnull(FirstB)
| where FirstA < TimeGenerated and FirstB <= TimeGenerated
| summarize Calls = make_list(strcat(ToolName, " (", Decision, ")")),
            Allowed = countif(Decision == "allowed"),
            FirstA = min(FirstA)
    by SessionId, Agent, UserUpn
| extend Severity = iff(Allowed > 0, "High", "Medium")
| project SessionId, Agent, UserUpn, Severity, FirstA, Calls
```

```kql
// Hunt: agents using legs their threat model says they don't have
let Declared = datatable(Agent:string, DeclaredLegs:dynamic, Registered:bool) [
    "ask-northwind",      dynamic(["A","B","C"]), true,
    "ap-inbox-assistant", dynamic(["A","B","C"]), true,
    "web-research",       dynamic(["A","C"]),     true,
    "deploy-helper",      dynamic(["B","C"]),     true
];
// Paste the ToolRegister let statement from the first query here
NorthwindAgentGateway_CL
| where TimeGenerated > ago(7d)
| lookup kind=leftouter ToolRegister on ToolName
| extend Legs = iff(isnull(Registered), dynamic(["A","B","C"]), Legs)
| project-away Registered
| mv-expand Leg = Legs to typeof(string)
| summarize ObservedLegs = make_set(Leg), Tools = make_set(ToolName) by Agent
| lookup kind=leftouter Declared on Agent
| where isnull(Registered)
     or array_length(set_difference(ObservedLegs, DeclaredLegs)) > 0
| extend Undeclared = iff(isnull(Registered), ObservedLegs,
                          set_difference(ObservedLegs, DeclaredLegs))
| project Agent, Undeclared, ObservedLegs, DeclaredLegs, Tools
```

On the sample, the alert returns **3 rows** (S-502 High, S-505 Medium, S-508
High) and the hunt returns **1 row** (`deploy-helper`, undeclared leg A). I
ran the same logic in Python over the 23 rows:

```
rows 23 sessions 9 agents 4 users 8
decision Counter({'allowed': 22, 'denied': 1}) approval Counter({'none': 21, 'human': 2})

Rule A
S-501 ask-northwind m.ito legs B firstA None firstB 21:02:10 [] -
S-502 ask-northwind h.nguyen legs ABC firstA 21:15:05 firstB 21:15:05 [('issue_refund', 'allowed')] High
S-503 ask-northwind p.dalton legs ABC firstA 21:30:00 firstB 21:30:00 [] -
S-504 ask-northwind r.kaur legs ABC firstA 21:45:10 firstB 21:45:10 [] -
S-505 ask-northwind c.brennan legs ABC firstA 22:05:00 firstB 22:05:00 [('send_email', 'denied')] Medium
S-506 ap-inbox-assistant l.foster legs ABC firstA 22:20:00 firstB 22:20:00 [] -
S-507 web-research j.marsh legs AC firstA 22:40:00 firstB None [] -
S-508 deploy-helper k.obrien legs ABC firstA 23:00:40 firstB 23:00:00 [('run_pipeline', 'allowed')] High
S-509 deploy-helper k.obrien legs BC firstA None firstB 23:20:00 [] -

Rule B (drift)
ask-northwind observed ABC declared ABC undeclared []
ap-inbox-assistant observed ABC declared ABC undeclared []
web-research observed AC declared AC undeclared []
deploy-helper observed ABC declared BC undeclared ['A'] -> DRIFT
```

What it excludes: S-503 and S-506 (the C call had human approval), S-504 (the
refund came *before* the external ticket), S-507 (no B leg) and S-501 and
S-509 (no A leg). In S-508 the `fetch_url` call doesn't fire on its own row,
because it's the call that *brought in* the A leg, and the rule needs A to
come strictly before. The `run_pipeline` call 50 seconds later does fire.

**What I verified and what I didn't.** The gateway table, its columns, the
register and every agent are invented. `datatable`, `lookup`, `minif`,
`set_has_element`, `set_difference`, `mv-expand ... to typeof()`,
`make_list` and `make_set` are standard KQL. Neither query has been run
against a live workspace, only the Python equivalent. One KQL detail to test
before relying on it: the register is joined with `lookup`, and a tool with
no match gets a null `Registered`, which is what the `iff` uses to treat it
as all three legs. The sample has no unregistered tool, so that branch is
untested here.

**Tuning note:** the 1-day and 7-day windows are my starting points, not
published figures. Expect the alert to be noisy at first for Ask Northwind,
because "customer emails asking for a refund, agent refunds" is the normal
business flow. That isn't a reason to tune it out. It's a reason to fix the
taint rule so the action needs confirmation, after which the alert only fires
when the gateway's own policy has failed. The rule is only as good as the
register. If a tool is scored wrongly, such as `fetch_url` marked as A only,
the alert silently misses it, so the register needs an owner and a review
whenever a tool is added. The approval check trusts `Approval = human`,
which says nothing about whether the person read what they approved. Day 17
(tool permissions) and Day 19 (logging) come back to both problems.

---

## Your turn

1. Northwind HR wants an onboarding agent that reads candidates' emailed CVs,
   looks up the HR system, and sends welcome emails to candidates' personal
   addresses. Score its legs tool by tool, then propose which leg to remove
   or gate, and what that costs HR. (Day 9's deepfake candidates are a good
   reason to care.)
2. S-502 fired even though Northwind had switched on a taint rule. Explain
   why, and rewrite the taint rule in one or two sentences so the same kind
   of gap can't happen when the next tool is added.
3. `web-research` is [AC] and the alert ignores it. Using Willison's update
   and Ayzenberg's reply, describe one harmful thing an injected page could
   make it do with no B leg, and decide whether that deserves its own rule.
4. You pick up the S-508 alert. List the first three things you'd check, and
   then choose between removing `fetch_url`, requiring approval for
   `run_pipeline` after any A-leg call, or running web lookups in a separate
   session. Justify the choice in terms of what the engineers lose.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Simon Willison: [The lethal trifecta for AI agents: private data, untrusted content, and external communication](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) · [New prompt injection papers: Agents Rule of Two and The Attacker Moves Second](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/) (the [A]+[C] caveat and Meta's response)
- Meta AI: [Agents Rule of Two: A Practical Approach to AI Agent Security](https://ai.meta.com/blog/practical-ai-agent-security/)
- Chromium: [The Rule Of 2](https://chromium.googlesource.com/chromium/src/+/main/docs/security/rule-of-2.md)
- Beurer-Kellner et al.: [Design Patterns for Securing LLM Agents against Prompt Injections](https://arxiv.org/abs/2506.08837) (six patterns for constraining an agent once it has read untrusted input)
- MITRE ATLAS: [AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data](https://atlas.mitre.org/mitigations/AML.M0030) · [AML.T0086 Exfiltration via AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0086) · [AML.T0053 AI Agent Tool Invocation](https://atlas.mitre.org/techniques/AML.T0053)
- OWASP GenAI Security Project: [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/) (ASI01 Agent Goal Hijack and ASI02 Tool Misuse are the risks today's rule watches for)
- This log: [ANALYSIS.md, section 2](../ANALYSIS.md#start-with-blast-radius) (blast radius first) · [Day 10](2026-11-12-owasp-llm-top-10.md) (Ask Northwind's tools and the first external ticket) · [Day 12](2026-11-14-indirect-prompt-injection-echoleak.md) (why a classifier won't save you, and image rendering as an exit) · [Day 4](2026-11-06-payment-controls-callbacks-dual-approval.md) (the call-back that gates the AP agent)

⬅️ [Learning log index](README.md) · ➡️ Day 14: Input handling: what sanitisation can and can't do (16 Nov)
