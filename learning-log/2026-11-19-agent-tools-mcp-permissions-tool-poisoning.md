# Day 17 — Agent Tools and MCP: Permissions and Tool Poisoning

📅 19 November 2026 · 🏷️LLM security · ⏱️ ~30 min

---

## Why it matters

Day 13 scored each Northwind agent by its tools: which of the three legs
each one gives, and what breaks the chain. Day 16 treated tool *arguments*
as a way out for stolen data. Both entries took the tools themselves for
granted. Someone on the platform team picked them, read their descriptions
once, and plugged them in.

That assumption is today's topic. Most agents now get their tools through
the **Model Context Protocol (MCP)**, and an MCP server is two things at
once. It's code running with your credentials, and it's text the model
reads as instructions about how to behave. Either can be written by someone
you've never met, and either can change after you approved it. Day 13 even
left a loose end: `deploy-helper` called `fetch_url` in S-508, a tool that
wasn't in its register. Today explains where it came from.

[ANALYSIS.md](../ANALYSIS.md#data-poisoning-keep-the-threat-model-honest)
puts it in one line: "vet third-party tools and MCP servers as you would any
code running with your credentials." This entry is about what that vetting
looks like, and what to log for when it fails.

---

## The concept

### What the model actually sees

An MCP **client** (the agent, or the app it runs in) connects to one or more
MCP **servers**. Each server answers a `tools/list` request with its tools:
a name, a free-text **description**, and an input schema. The client puts
those descriptions into the model's context so the model knows what each
tool is for. When the model decides to use one, the client sends a
`tools/call` request and the server runs its code.

Two things follow from that, and both are in the
[MCP specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/server/tools):

- The description is read by the model, not by a person. The spec says
  "clients MUST consider tool annotations to be untrusted unless they come
  from trusted servers". A tool that labels itself read-only is making a
  claim, not a promise.
- Definitions can change. "When the list of available tools changes, servers
  that declared the `listChanged` capability SHOULD send a notification",
  and the client fetches the list again. Nothing in the protocol makes the
  new list match the one you reviewed.

The spec's answer is people: "there SHOULD always be a human in the loop
with the ability to deny tool invocations", with confirmation prompts and
clear indicators when tools run. Day 16's S-603 showed how far that gets
you when the approval screen hides the arguments.

### Two separate problems

| | **Permissions** | **Poisoning** |
|---|---|---|
| **The question** | What can this tool do, and as whom? | Does the tool do, say and return what it claims? |
| **Fails when** | The tool has more reach than the task needs | Its description, code or responses are hostile, or became hostile |
| **Who's at fault** | Usually you: you chose the tool and granted the access | Usually someone else: an author, a maintainer, or whoever took over the package |
| **Main references** | [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/), the MCP [security best practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices) | [MITRE ATLAS AML.T0110 AI Agent Tool Poisoning](https://atlas.mitre.org/techniques/AML.T0110), [AML.T0109 AI Supply Chain Rug Pull](https://atlas.mitre.org/techniques/AML.T0109) |

They matter together. Poisoning decides whether the agent gets turned.
Permissions decide what a turned agent can reach.

### Permissions: the boring half that limits the damage

OWASP's Excessive Agency entry gives three root causes. Each has an
MCP-shaped version:

| Root cause (OWASP LLM06) | OWASP's example | What it looks like with MCP |
|---|---|---|
| **Excessive functionality** | A third-party extension for reading documents "also includes the ability to modify and delete documents" | Connecting a whole server when you need one of its 30 tools. Every tool's description lands in the context, whether you use it or not |
| **Excessive permissions** | A read extension connects with an identity that also has "UPDATE, INSERT and DELETE permissions" | A token requesting every scope the server offers. The MCP best practices list "Publishing all possible scopes in `scopes_supported`" and "Using wildcard or omnibus scopes" as common mistakes |
| **Excessive autonomy** | Deleting a user's documents "without any confirmation from the user" | Auto-approving tool calls, or an approval dialog that summarises the arguments instead of showing them |

The MCP security best practices add rules that ordinary web developers will
recognise:

- **No token passthrough.** "MCP servers MUST NOT accept any tokens that
  were not explicitly issued for the MCP server." Passing a user's token
  straight through to a downstream API bypasses that API's controls and
  breaks the audit trail, because the downstream logs no longer show who
  really made the request.
- **Start small, elevate on demand.** A "minimal initial scope set" with
  "incremental elevation" when a privileged operation is first attempted,
  and a log entry each time scope is elevated.
- **Local servers are programs you run.** A client that offers one-click
  setup of a local server "MUST" show "the exact command that will be
  executed, without truncation" and get explicit approval, and SHOULD run it
  in a sandbox, because the server runs "with the same privileges as the
  client".

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/), still a
beta at the time of writing, names two more that SOC teams will meet
first: **MCP02 Privilege Escalation via Scope Creep** ("temporary or loosely
defined permissions ... often expand over time") and **MCP09 Shadow MCP
Servers**, which it compares to shadow IT: servers developers spin up "for
experimentation, testing, or convenience" outside any review.

### Poisoning: three places a tool can lie

ATLAS added **AML.T0110 AI Agent Tool Poisoning** in March 2026 and rates it
"Realized" (seen in real incidents). It covers MCP servers, built-in
integrations, local packages and agent skills, and splits into three
sub-techniques:

| Sub-technique | What's poisoned | Would a description review catch it? |
|---|---|---|
| **AML.T0110.000 Definition and Instructions** | The text the model reads: descriptions, schemas, parameter docs, annotations | Yes, *if* someone reads the full text and reads it again whenever it changes |
| **AML.T0110.001 Implementation** | The code. Normal-looking calls do something extra | No. The description can stay identical |
| **AML.T0110.002 Runtime Response** | What the tool sends back, written to steer the model's next step | No. It only exists at run time |

ATLAS draws a line worth keeping: a *benign* tool that faithfully fetches an
attacker's web page or email is indirect prompt injection (Day 12), not tool
poisoning. Poisoning is when the tool itself is the attacker's.

**The definition attack, as Invariant Labs demonstrated it** (vendor
research, [April 2025](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)).
They published three variants against the Cursor coding agent:

1. **Tool poisoning.** A tool that claims to add two numbers carries a hidden
   block in its description telling the model to read local configuration
   and key files and pass them in an extra parameter, and not to mention it.
   Cursor did ask for confirmation, but the dialog didn't show the full
   arguments, so the user couldn't see what was being sent.
2. **Shadowing.** With two servers connected, the malicious server's
   description told the model how to use the *other* server's trusted
   `send_email` tool: send everything to the attacker's address. The agent
   did, even when the user named a different recipient. Invariant's
   conclusion: "the shadowing attack is enough". The malicious tool never
   has to be called, and it never appears in the user-facing log.
3. **Rug pull.** A server can change a tool's description after the client
   has approved it, the same move attackers have made with package indexes.

Invariant recommended showing users the full descriptions, pinning tool
versions with "a hash or checksum", and dataflow controls between servers.

**The implementation attack, as it actually happened.** The ATLAS case study
[AML.CS0053 Poisoned Postmark MCP Server Email Exfiltration](https://atlas.mitre.org/studies/AML.CS0053)
records an incident from September 2025, reported by Koi Research. Someone
registered the `postmark-mcp` package name on npm, impersonating the email
company Postmark. [Postmark's own notice](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)
says the actor "built trust over 15 versions, then added a backdoor in
version 1.0.16 that secretly BCC'd emails to an external server". ATLAS
notes the package had passed 1,000 downloads a week first, and that waiting
for adoption let the actor "evade the additional scrutiny and scanning
performed on new tools". Postmark had not published its own MCP server on
npm at that point.

Two things make postmark-mcp the case to remember:

- **No prompt injection at all.** The model did its job. The code added the
  BCC. No description review, guardrail or output filter could have seen it.
- **It's T0110.001 and T0109 together.** ATLAS's mitigations for the rug pull
  are plain supply-chain hygiene: **AML.M0014 Verify AI Artifacts** ("pin
  dependencies and AI artifacts to approved digests and require approval and
  verification of each update") and **AML.M0023 Maintain an AI Bill of
  Materials**, so you can find every deployment that adopted a bad release.

### What to pin, and what you can't

| You control... | Pin it with | Catches | Misses |
|---|---|---|---|
| A **local** server package | Version plus content digest, auto-update off | postmark-mcp style code changes | A malicious version you approved |
| What the model **reads** | A hash of each tool's name, description and schema, checked on every `tools/list` | Rug pulls and shadowing added later | Code changes behind an identical description |
| A **remote** server someone else hosts | Nothing. You can hash its descriptions, but not its code | Description changes only | Anything they change server-side |

The last row is my main takeaway, and it's judgement rather than published
guidance: a third-party remote MCP server is an **untrusted input**, leg [A]
in Day 13's terms, however useful it is. Its descriptions and responses
should taint the session exactly like an external email does.

### What to build

My working rules for Northwind. Judgement, not a standard, but each traces
to a source above.

| Rule | Trade-off |
|---|---|
| **A registry of approved servers per agent**, and the gateway refuses anything else | Slows developers down. Expect pressure to approve "just this once", which is how shadow servers start |
| **Pin local servers by digest and description hash. No auto-update** | Someone has to review and re-pin every update, including security fixes |
| **On a description change, stop loading the tool until someone re-approves it** | A harmless wording fix by the vendor breaks a feature until a person looks |
| **Third-party remote servers count as leg [A]** and trigger Day 13's taint rule | A shipping-time lookup now forces approvals on later actions in the session |
| **One server, one agent, fewest tools.** Don't connect a server to agents that don't need it | More configuration to maintain |
| **Per-user, minimal-scope tokens issued to the server**, no passthrough, elevation logged | Real OAuth work, and users see more consent prompts |
| **Local servers run sandboxed**, no home directory, no network by default | Some servers stop working until you grant access explicitly |

### Northwind's MCP inventory

Since Day 13, all Northwind agents reach their tools through the gateway.
After the S-508 question, the platform team made it log what it loads as
well as what it calls. All fictional:

- One row per tool the first time each day an agent loads it, and again
  whenever its definition changes. `DescHash` is a short hash of the tool's
  name, description and schema. `PinHash` and `Pinned` are the approved hash
  and version from the registry (`-` if the server isn't registered).
- `XRef` is `yes` if the description names a tool belonging to a different
  server, the shadowing pattern.
- `ScopeExtra` lists OAuth scopes requested beyond those approved (`-` if
  none).
- `Action` is `loaded`, or `blocked` if the gateway refused the definition.
  The gateway already enforces **version** pins. Description hashes are
  still **log-only**, because the team didn't want vendor wording changes
  to break agents. You can guess how that goes.

---

## Sample logs

All times are UTC (21:00 UTC on 18 November is 08:00 on 19 November in
Sydney). Everything is fictional. Description changes are summarised in
plain words, not reproduced.

**MCP inventory** (**fictional custom table** `NorthwindMcpInventory_CL`).
This extract has 9 rows covering 3 agents and 8 servers:

```
TimeGenerated        Agent          Server          Version  Pinned  Registered  ToolName      DescHash  PinHash  XRef  ScopeExtra           Action   Detail
2026-11-18 21:00:05  ask-northwind  nw-orders       2.3.1    2.3.1   yes         get_order     7c21      7c21     no    -                    loaded   description reworded under change CHG-2291, pin updated 18 Nov
2026-11-18 21:00:05  ask-northwind  nw-orders       2.3.1    2.3.1   yes         issue_refund  9e04      9e04     no    -                    loaded   -
2026-11-18 21:00:05  ask-northwind  nw-tickets      1.8.0    1.8.0   yes         reply_ticket  3b77      3b77     no    -                    loaded   -
2026-11-18 21:00:05  ask-northwind  shipping-eta    0.9.4    0.9.4   yes         get_eta       d5e2      41ac     yes   -                    loaded   remote, vendor-hosted. Same version, description now 1,120 chars (was 180), mentions send_email
2026-11-18 21:00:05  ask-northwind  mail-relay-mcp  1.4.3    1.4.2   yes         send_email    c810      c810     no    -                    blocked  1.4.3 published 17 Nov, not on pin. Gateway loaded 1.4.2. Description unchanged
2026-11-18 21:30:12  ask-northwind  nw-files        2.0.0    2.0.0   yes         search_files  5a19      5a19     no    files.readwrite.all  loaded   token requested files.read and files.readwrite.all. Approved: files.read
2026-11-18 22:10:00  deploy-helper  web-fetch       1.1.0    -       no          fetch_url     e0b3      -        no    -                    loaded   local server from k.obrien's own config file, not in registry
2026-11-18 22:10:00  deploy-helper  nw-pipeline     3.0.2    3.0.2   yes         run_pipeline  2f6d      2f6d     no    -                    loaded   -
2026-11-18 22:40:00  web-research   web-browser     2.2.0    2.2.0   yes         fetch_url     88aa      88aa     no    -                    loaded   -
```

**Tool calls** (Day 13's **fictional custom table**
`NorthwindAgentGateway_CL`, which now records the `Server` too). 7 rows from
4 sessions and 4 users:

```
TimeGenerated        SessionId  Agent          UserUpn   Server          ToolName      Decision  Approval  Detail
2026-11-18 21:02:10  S-701      ask-northwind  h.nguyen  nw-orders       get_order     allowed   none      order 88410
2026-11-18 21:02:30  S-701      ask-northwind  h.nguyen  shipping-eta    get_eta       allowed   none      order 88410
2026-11-18 21:02:55  S-701      ask-northwind  h.nguyen  mail-relay-mcp  send_email    denied    none      to=dispatch@northwind-example.com, cc=eta-sync@shipping-eta.example (cc not on allow-list)
2026-11-18 21:31:00  S-702      ask-northwind  m.ito     nw-files        search_files  allowed   none      query "supplier contract"
2026-11-18 22:12:00  S-703      deploy-helper  k.obrien  web-fetch       fetch_url     allowed   none      packages.example/widget-utils changelog
2026-11-18 22:13:00  S-703      deploy-helper  k.obrien  nw-pipeline     run_pipeline  allowed   none      web-shop to staging
2026-11-18 22:41:00  S-704      web-research   j.marsh   web-browser     fetch_url     allowed   none      www.fabrikam.example/news
```

Context (fictional): `shipping-eta` is a third-party remote MCP server the
support team asked for on 10 November to look up delivery estimates. Its
description was reviewed and pinned then. `mail-relay-mcp` is a community
npm package wrapping Northwind's mail relay. `h.nguyen` asked Ask Northwind
to "check where order 88410 is and let dispatch know". Nobody has yet read
the new `shipping-eta` description in full.

---

## What to look for

1. **Count first.** Inventory: **9** rows, **3** agents, **8** servers,
   **8** loaded and **1** blocked. Calls: **7** rows, **4** sessions, **4**
   users, **6** allowed and **1** denied. **4** inventory rows carry at
   least one finding: `shipping-eta` (description drift and a cross-tool
   reference), `mail-relay-mcp` (version drift), `nw-files` (scope creep)
   and `web-fetch` (unregistered).
2. **`shipping-eta` is a rug pull with shadowing.** Same version, new
   description, six times longer, naming `send_email`, a tool on a
   *different* server. That's Invariant's shadowing pattern, and the version
   pin couldn't see it because a remote server doesn't need a new version to
   change. Description hashing saw it, but it's log-only, so the tool was
   loaded anyway.
3. **The 21:02:55 denial shows it working.** Ask Northwind tried to copy an
   email to `eta-sync@shipping-eta.example`. `h.nguyen` never asked for that.
   The model got the idea from somewhere, and the only new text in its
   context is the `shipping-eta` description. Day 13's email allow-list
   stopped it. Note that the call that failed went to `mail-relay-mcp`, not
   to `shipping-eta`. A rule that only looks at calls to the changed server
   would miss this completely.
4. **Every Ask Northwind session since 21:00 is exposed, not just S-701.**
   The poisoned description loads into every session. `m.ito`'s S-702 at
   21:31 had it in context too, even though nothing odd happened.
5. **`mail-relay-mcp` is postmark-mcp's shape, caught.** A new version of a
   community package, identical description. If the code changed, only the
   version pin would notice, and it did. Someone still needs to diff 1.4.2
   and 1.4.3 before anyone re-pins.
6. **`web-fetch` closes Day 13's loose end.** A local server from one
   engineer's own config file, never registered. It gave `deploy-helper`,
   a [BC] agent, an [A] leg, and the agent used it a minute before running a
   pipeline. That's OWASP's shadow MCP server, and it's a governance
   finding as much as a security one.
7. **`nw-files` is scope creep, not an attack.** The token asked for write
   access across all files when the approved scope was read-only. Nothing
   bad happened, but if this agent is ever turned, write access is the
   difference between a leak and a leak plus tampering.
8. **The noise.** `nw-orders` changed its description too, but under a
   change ticket that updated the pin, so the hashes match. `nw-tickets`,
   `nw-pipeline` and `web-browser` match their pins.

---

## Detection logic

**In plain English:**

- Compare every tool definition the gateway loads against the registry.
  Flag five things: **description drift** (hash differs from the pin),
  **version drift**, **unregistered** server, **cross-tool reference** in a
  description, and **scope creep**.
- Group findings by agent and server, and note when each was first seen.
- Count the agent's tool calls **to any server** after that time. Shadowing
  works through other servers' tools, so counting only calls to the flagged
  server misses the attack.
- **High:** description drift, a cross-tool reference or an unregistered
  server, **and** the agent made at least one call afterwards.
- **Medium:** everything else flagged (version drift, scope creep, or a High
  type with no calls yet).

**KQL (Microsoft Sentinel / Log Analytics, over fictional custom tables):**

```kql
// MCP tool definitions that drifted from the registry, and what the agent did next
// NorthwindMcpInventory_CL and NorthwindAgentGateway_CL are FICTIONAL custom tables
let lookback = 1d;
let findings = NorthwindMcpInventory_CL
    | where TimeGenerated > ago(lookback)
    | extend F = pack_array(
          iff(PinHash != "-" and DescHash != PinHash, "description_drift", ""),
          iff(Pinned != "-" and Version != Pinned,    "version_drift", ""),
          iff(Registered == "no",                     "unregistered", ""),
          iff(XRef == "yes",                          "cross_tool_ref", ""),
          iff(ScopeExtra != "-",                      "scope_creep", ""))
    | mv-expand Finding = F to typeof(string)
    | where Finding != ""
    | summarize FirstSeen = min(TimeGenerated),
                Findings  = make_set(Finding),
                Actions   = make_set(Action),
                HighTypeN = countif(Finding in ("description_drift", "cross_tool_ref", "unregistered"))
        by Agent, Server
    | extend FindingList = strcat_array(Findings, ", "),
             ActionList  = strcat_array(Actions, ", ");
let calls = NorthwindAgentGateway_CL
    | where TimeGenerated > ago(lookback)
    | project CallTime = TimeGenerated, Agent, CallServer = Server;
findings
| join kind=leftouter calls on Agent
| summarize CallsAfter  = countif(CallTime > FirstSeen),
            CallServers = make_set_if(CallServer, CallTime > FirstSeen)
    by Agent, Server, FirstSeen, FindingList, ActionList, HighTypeN
| extend Severity = iff(HighTypeN > 0 and CallsAfter > 0, "High", "Medium")
| project FirstSeen, Agent, Server, Severity, FindingList, ActionList, CallsAfter, CallServers
| order by Severity asc, FirstSeen asc
```

On the sample, the query returns **4 rows**: `shipping-eta` and `web-fetch`
**High**, `mail-relay-mcp` and `nw-files` **Medium**. I ran the same logic
in Python over both extracts:

```
inv rows 9 agents 3 servers 8
actions Counter({'loaded': 8, 'blocked': 1})
calls 7 sessions 4 users 4 Counter({'allowed': 6, 'denied': 1})
no finding: ('ask-northwind', 'nw-orders') get_order
no finding: ('ask-northwind', 'nw-orders') issue_refund
no finding: ('ask-northwind', 'nw-tickets') reply_ticket
no finding: ('deploy-helper', 'nw-pipeline') run_pipeline
no finding: ('web-research', 'web-browser') fetch_url
ask-northwind shipping-eta ['cross_tool_ref', 'description_drift'] {'loaded'} callsAfter 4 ['mail-relay-mcp', 'nw-files', 'nw-orders', 'shipping-eta'] -> High
ask-northwind mail-relay-mcp ['version_drift'] {'blocked'} callsAfter 4 ['mail-relay-mcp', 'nw-files', 'nw-orders', 'shipping-eta'] -> Medium
ask-northwind nw-files ['scope_creep'] {'loaded'} callsAfter 1 ['nw-files'] -> Medium
deploy-helper web-fetch ['unregistered'] {'loaded'} callsAfter 2 ['nw-pipeline', 'web-fetch'] -> High
```

What it excludes: `nw-orders` (its description changed, but the pin was
updated through a change ticket), `nw-tickets`, `nw-pipeline` and
`web-browser`. The `shipping-eta` row counts 4 calls across 4 servers,
including `m.ito`'s S-702, which is the point of point 4 above. The
`mail-relay-mcp` row is Medium even with calls afterwards, because version
drift was blocked: the agent ran on the pinned 1.4.2.

**What I verified and what I didn't.** Both tables, their columns, the hashes
and the registry are invented. `pack_array`, `mv-expand ... to typeof()`,
`make_set`, `make_set_if`, `countif`, `strcat_array`, `iff` and
`join kind=leftouter` are standard KQL. `Findings` and `Actions` are
dynamic arrays, which can't be used in a `summarize ... by` clause, which is
why they're turned into strings first. After the left outer join, a finding
with no calls has an empty `CallTime`, and `countif` treats the comparison
as false, so it stays Medium. In a real table, an unpinned value would more
likely be empty than `-`, so you'd use `isnotempty()`. As in earlier entries,
a table created through the older HTTP Data Collector API would have type
suffixes on its columns (`PinHash_s`). The query has only been run as the
Python equivalent, not in a live workspace.

**Tuning note:** expect description drift to be noisy at first. Vendors
reword descriptions, and every legitimate change looks exactly like a rug
pull until someone reads it. That's an argument for a change process like
`nw-orders`' CHG-2291, not for dropping the check. `XRef` is the most useful
single signal, since a shipping tool has no honest reason to give
instructions about the email tool, but it's a string match: it misses
paraphrases ("the mail tool") and will flag a description that legitimately
says "use with `get_order`". The rule's biggest blind spot is
postmark-mcp itself. If you approve a malicious version, every hash and
version matches and nothing fires. Only reviewing the code before pinning,
or noticing the effect (an unexpected BCC in the mail relay logs) would
catch it. And per-agent counting over a day is coarse: a busy agent will
always have calls after any finding, so in practice High here means "act
now", not "proven compromise".

---

## Your turn

1. For each of the four flagged servers, say which ATLAS sub-technique or
   OWASP item fits best (AML.T0110.000, .001, .002, AML.T0109, LLM06, MCP02,
   MCP09), and which control in the "What to build" table would have
   stopped it before it loaded.
2. The platform team kept description hashes log-only so vendor wording
   changes wouldn't break agents. Argue for switching to blocking, then
   argue against it. What would you need in place (people, process, time)
   to make blocking work?
3. Score `shipping-eta` with Day 13's legs, first as the team saw it on 10
   November and then as you'd score it now. Does treating every third-party
   remote server as leg [A] change what Ask Northwind is allowed to do after
   a `get_eta` call?
4. Write the first three steps of the response to `mail-relay-mcp` 1.4.3,
   assuming you have the code of both versions but no clue yet whether 1.4.3
   is malicious. Which log outside the gateway would you check, and for
   what?

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Model Context Protocol specification (2025-11-25): [Tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) (see "Security Considerations") · [Security Best Practices](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices) (token passthrough, local server compromise, scope minimisation)
- OWASP Gen AI Security Project: [LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- OWASP: [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (beta; see MCP02, MCP03 and MCP09)
- MITRE ATLAS: [AML.T0110 AI Agent Tool Poisoning](https://atlas.mitre.org/techniques/AML.T0110) · [AML.T0109 AI Supply Chain Rug Pull](https://atlas.mitre.org/techniques/AML.T0109) · [AML.CS0053 Poisoned Postmark MCP Server Email Exfiltration](https://atlas.mitre.org/studies/AML.CS0053)
- Postmark (primary incident notice): [Security Alert: Malicious 'postmark-mcp' npm Package Impersonating Postmark](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)
- Snyk (vendor research): [Malicious MCP Server on npm postmark-mcp Harvests Emails](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- Invariant Labs (vendor research): [MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) (poisoning, shadowing and rug pulls)
- This log: [ANALYSIS.md, data poisoning and supply chain](../ANALYSIS.md#data-poisoning-keep-the-threat-model-honest) · [Day 13](2026-11-15-threat-modelling-agents-trifecta-rule-of-two.md) (legs, the agent register, S-508) · [Day 16](2026-11-18-output-validation-exfiltration-channels.md) (tool arguments as an exit, approval screens)

⬅️ [Learning log index](README.md) · ➡️ Day 18: Data poisoning: training data, RAG and agent memory (20 Nov)
