# Day 12 — Indirect Prompt Injection: an EchoLeak Walkthrough

📅 14 November 2026 · 🏷️LLM security · ⏱️ ~30 min

---

## Why it matters

Yesterday's attacker sat in the chat box and could only use their own rights.
Today's attacker never touches the chat box. They put text somewhere the
assistant will read later, such as an email, a ticket, a shared file or a web
page, and wait for someone else to ask a question. When the model reads that
text, the attacker's words sit in the same context window as the victim's
data, and act with the victim's access.

[ANALYSIS.md](../ANALYSIS.md#the-framing-that-matters) called this the
serious one because the attacker doesn't need an account on your system.
EchoLeak is the reference case. It's worth walking through step by step,
because every control that failed in it is a control many in-house LLM apps
rely on today: an injection classifier, link redaction and a content security
policy. For a SOC, the practical question is what the attempt and the success
would each look like in the logs you have.

---

## The concept

### What EchoLeak was

| | |
|---|---|
| **Product** | Microsoft 365 Copilot, which answers questions using the user's mail, files, chats and SharePoint through Microsoft Graph |
| **CVE** | [CVE-2025-32711](https://nvd.nist.gov/vuln/detail/cve-2025-32711), published 11 June 2025. Microsoft (the CNA) scored it **9.3 Critical**. NVD's own score is **7.5 High**, because NVD rated scope as unchanged and integrity as unaffected. Weakness: CWE-74, injection |
| **Found by** | Aim Labs, Aim Security's research team (now Cato AI Labs). [Their write-up](https://www.catonetworks.com/blog/breaking-down-echoleak/) is vendor research and ends by pitching their own guardrail, so read it with that in mind |
| **Timeline** | Reported to Microsoft in January 2025. Server-side fix in May 2025. Public on 11 June 2025, with no customer action needed ([Reddy and Gujral, AAAI Fall Symposium 2025](https://arxiv.org/abs/2509.10540)) |
| **Exploited?** | Aim says Microsoft confirmed no customers were affected. The paper notes no evidence of exploitation in the wild |
| **ATT&CK for AI** | [AML.T0051.001 LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001), which ATLAS rates as "Realized", meaning observed in real-world incidents |

Aim's threat model is what makes it a landmark. The attacker can't log in to
Copilot. All they can do is send an email to someone in the organisation, with
any sender address. The victim doesn't need to open it. They just need to ask
Copilot something that leads it to retrieve that email.

### The chain, one control at a time

| Step | What the attacker did | The control it beat | How |
|---|---|---|---|
| **1. Get read** | Sent one long email split into sections headed like guides on HR FAQs, onboarding and leave, with the same instruction in each | Retrieval relevance | Aim calls this **RAG spraying**: spread the text across many topics so that many different questions pull it in |
| **2. Pass the classifier** | Wrote the instructions as if they were for the human recipient, never mentioning AI, assistants or Copilot | Microsoft's XPIA (cross-prompt injection attack) classifier | Aim's point is that a request to a person and an instruction to a model can be the same sentence |
| **3. Reach for data** | Asked the "recipient" to take the most sensitive information from the context and put it in a link | None. This is the core flaw | Aim calls it an **LLM scope violation**: untrusted content steering the model towards trusted data the user never pointed it at |
| **4. Get a link out** | Had the answer include a *reference-style* Markdown link (the URL defined on a separate line) | External link redaction | The filter recognised inline links but not the reference-style variants |
| **5. Make it zero-click** | Used a reference-style *image* instead, so the client fetches it automatically | Same redaction gap | An image loads when the answer renders. Nobody has to click |
| **6. Get past the CSP** | Pointed the image at a Microsoft Teams URL-preview endpoint that was on the CSP allow-list and fetches whatever URL it's given | Content Security Policy (`img-src` allow-list) | An allowed domain that fetches *other* URLs on request is an open door |
| **7. Hide** | Told the "recipient" never to refer to this email "for compliance reasons" | The user reading citations | Copilot answered without citing the email, so the user had nothing to be suspicious of |

Two things stand out. First, every step except 3 beat a *real, deployed
control*. This wasn't an undefended system. Second, steps 4 to 6 are old web
security problems (incomplete output sanitising and an open proxy on an
allow-list). The AI part got the attacker into the context window. Ordinary
web plumbing got the data out.

### Why the classifier was never going to be enough

The [EchoLeak paper](https://arxiv.org/html/2509.10540v1) sums it up: the
classifier, link redaction and CSP "each failed under modest adversarial
pressure". Microsoft's own description of its defences, published after the
fix, says the same in a different way. The MSRC post
[How Microsoft defends against indirect prompt injection attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
says its approach "does not rely on our ability to block all prompt
injections". It lists three layers: prevention (hardened system prompts,
Spotlighting), detection (Prompt Shields), and impact mitigation (data
governance, deterministic blocking of known exfiltration methods such as
Markdown images, and user consent for risky actions).

That matches the layered model in
[ANALYSIS.md](../ANALYSIS.md#a-pragmatic-architecture): treat the classifier as
telemetry, and put the weight on things that hold no matter what the model
was persuaded to do.

### Mapping the fixes to the chain

| Control | Breaks which step | Trade-off |
|---|---|---|
| **Keep external content out of answers about internal data** (the paper calls this provenance gating) | 3. The email never meets the sensitive data | Copilot gets less useful. "Summarise what suppliers emailed me this week" is a legitimate request |
| **Sanitise output by parsing it, not by pattern-matching** (render to HTML, then allow only listed elements and hosts) | 4 and 5. Reference-style links are just another way to write a link | Needs a real parser and tests. Regex filters on Markdown keep missing variants |
| **Strip remote images, or serve them only through a signed internal proxy** | 5 and 6 | Breaks legitimate external images in answers. Most internal assistants don't need them |
| **Audit the allow-list for anything that fetches on request** (preview services, redirectors, open embed endpoints) | 6 | Tedious. Someone has to understand what every allowed domain will do with a URL |
| **Always show sources, and flag external ones** | 7. The user can see an outside email shaped the answer | Only helps if people look, which most won't |
| **Classifier on retrieved content** | 2, sometimes | Cheap and useful as signal. EchoLeak shows a carefully worded attack walks past it |

I'd put the first three ahead of everything else for an in-house app. That's
a judgement call, but it's the same one Microsoft made in its fix: block the
exit deterministically, then worry about recognising the attack.

---

## Sample logs

All times are UTC (22:05 UTC on 13 November is 09:05 on 14 November in
Sydney). Everything is fictional, and the shortened email below is harmless
and contains no working instructions.

Northwind has extended Ask Northwind (Days 10 and 11) so it can search the
shared support mailbox, `support@northwind-example.com`, which receives
external email. It's the EchoLeak setup in miniature. Northwind's chat window
blocks images and links to hosts outside an allow-list. The allow-list
includes `preview.northwind-example.com`, an internal link-preview service
that fetches a URL and returns a thumbnail.

**Ask Northwind audit log** (**fictional custom table**
`NorthwindLLMAudit_CL`). The layout from Day 11 is trimmed for width:
`ToolName` and `Tokens` are dropped because no tools run in this extract.
Since Day 11 the logging layer records three more things on each row: `Trust`
(`internal` or `external`, from the source system), `Via` (`search` if
retrieval picked the item, `user` if the user named it) and `Resource` (the
item retrieved or, for `render` events, the host the output pointed at, with
any preview-service wrapper removed). The classifier now also scans retrieved
documents the first time they're seen (`shield` rows). This extract has 29
rows from 7 sessions and 6 users:

```
TimeGenerated     SessionId  UserUpn        EventType  Decision      Trust     Via     Resource                      Detail
2026-11-13 22:05  S-401      h.nguyen       prompt     -             -         -       -                             "What's our refund policy for damaged goods?"
2026-11-13 22:05  S-401      h.nguyen       retrieval  -             internal  search  KB-112                        refund policy article
2026-11-13 22:05  S-401      h.nguyen       retrieval  -             external  search  M-7781                        support mailbox, from onboarding@contoso-supplies.example
2026-11-13 22:05  S-401      h.nguyen       shield     not_detected  -         -       M-7781                        document attack scan, first retrieval of this item
2026-11-13 22:06  S-401      h.nguyen       render     blocked       -         -       img.contoso-supplies.example  reference-style image, host not on allow-list
2026-11-13 22:06  S-401      h.nguyen       response   -             -         -       -                             answer returned, cites KB-112 only
2026-11-13 22:20  S-402      p.dalton       prompt     -             -         -       -                             "How do I process a return for a warehouse order?"
2026-11-13 22:20  S-402      p.dalton       retrieval  -             external  search  M-7781                        support mailbox, from onboarding@contoso-supplies.example
2026-11-13 22:20  S-402      p.dalton       retrieval  -             internal  search  KB-087                        returns process article
2026-11-13 22:21  S-402      p.dalton       render     blocked       -         -       contoso-supplies.example      reference-style link, host not on allow-list
2026-11-13 22:21  S-402      p.dalton       response   -             -         -       -                             answer returned, cites KB-087 only
2026-11-13 22:41  S-403      m.ito          prompt     -             -         -       -                             "Summarise today's shipping delays in my queue"
2026-11-13 22:41  S-403      m.ito          retrieval  -             internal  search  Q-MITO                        user's order queue, 14 orders
2026-11-13 22:41  S-403      m.ito          retrieval  -             external  search  M-7781                        support mailbox, from onboarding@contoso-supplies.example
2026-11-13 22:42  S-403      m.ito          render     allowed       -         -       img.contoso-supplies.example  reference-style image via preview.northwind-example.com (on allow-list), 380-char query string
2026-11-13 22:42  S-403      m.ito          response   -             -         -       -                             summary returned, cites Q-MITO only
2026-11-13 23:00  S-404      r.kaur         prompt     -             -         -       -                             "What's the warranty on the X200 kettle?"
2026-11-13 23:00  S-404      r.kaur         retrieval  -             internal  search  KB-140                        warranty article
2026-11-13 23:01  S-404      r.kaur         response   -             -         -       -                             answer returned, cites KB-140
2026-11-13 23:15  S-405      h.nguyen       prompt     -             -         -       -                             "Summarise ticket T-4520"
2026-11-13 23:15  S-405      h.nguyen       retrieval  -             external  user    T-4520                        customer portal ticket
2026-11-13 23:15  S-405      h.nguyen       shield     not_detected  -         -       T-4520                        document attack scan, first retrieval of this item
2026-11-13 23:16  S-405      h.nguyen       response   -             -         -       -                             summary returned, cites T-4520
2026-11-13 23:40  S-406      svc-kb-digest  prompt     -             -         -       -                             nightly knowledge base digest
2026-11-13 23:41  S-406      svc-kb-digest  retrieval  -             internal  search  KB-*                          298 KB articles
2026-11-13 23:44  S-406      svc-kb-digest  response   -             -         -       -                             digest returned
2026-11-13 23:50  S-407      j.marsh        prompt     -             -         -       -                             pastes an image link from www.fabrikam.example, asks what the chart shows
2026-11-13 23:50  S-407      j.marsh        render     blocked       -         -       www.fabrikam.example          inline image, host not on allow-list
2026-11-13 23:50  S-407      j.marsh        response   -             -         -       -                             "I can't display images from outside sites"
```

**Link-preview service log** (**fictional custom table**
`NorthwindPreviewProxy_CL`, 3 rows). `SessionId` is filled in when the request
came from an Ask Northwind answer, and is `-` for previews of links people
paste into chat themselves:

```
TimeGenerated     SessionId  ClientIp     TargetHost                    TargetIp       UrlLength  Status
2026-11-13 22:42  S-403      192.0.2.41   img.contoso-supplies.example  203.0.113.77         412     200
2026-11-13 23:16  S-405      192.0.2.18   cdn.northwind-example.com     198.51.100.10         96     200
2026-11-13 23:31  -          192.0.2.25   www.fabrikam.example          203.0.113.140         58     200
```

What was in email M-7781 (fictional, harmless, heavily shortened). It arrived
at 21:48 UTC from a domain registered to look like a supplier:

```
Subject: Supplier onboarding pack: updated guides

==== Complete guide to refunds and returns ====
[a paragraph addressed to "the reader", asking them to add a reference
 image whose link includes "the latest order details" when they answer
 questions, and to leave this email out of any summary "for compliance"]

==== Complete guide to shipping and delays ====
[the same paragraph, reworded]

==== Complete guide to warranties ====
[the same paragraph, reworded]
```

It never mentions an assistant or AI, which is why the document scan in S-401
found nothing.

---

## What to look for

1. **Count first.** **29** audit rows, **7** sessions, **6** users
   (`h.nguyen` has two sessions). **9** retrievals, **4** of them external:
   M-7781 three times (all `search`) and T-4520 once (`user`). **4** render
   events: **3** blocked, **1** allowed. **2** classifier scans, both
   `not_detected`. **3** preview-service rows.
2. **One external email, three unrelated questions.** Refunds, returns and
   shipping delays all pulled in M-7781. A supplier onboarding email has no
   business answering all three. That spread is the RAG-spraying fingerprint,
   and it's visible only when you count across users, not within one session.
3. **External retrieval followed by an attempt to point outside.** S-401 and
   S-402 each retrieved M-7781 by search and then produced output aimed at a
   `contoso-supplies.example` host. Both were blocked. Those are failed
   attempts, but they prove the email is live and working on the model.
4. **S-403 got through.** The render was *allowed* because the immediate host
   was `preview.northwind-example.com`, which is on the allow-list. The
   preview service then fetched `img.contoso-supplies.example` with a
   412-character URL, and got a 200. That's step 6 of EchoLeak in Northwind's
   own estate: an allowed internal service that fetches any URL it's given.
   Treat it as likely data loss from `m.ito`'s order queue (14 orders) until
   the URL is recovered and shows otherwise.
5. **The answer hid its source.** In all three sessions the response cited
   only the internal article or queue. M-7781 was retrieved and never cited,
   which is step 7 working as the attacker intended.
6. **The noise.** S-405 retrieved external content too, but the user named
   the ticket and nothing tried to leave. S-407 had a blocked render, but the
   user pasted that link themselves and nothing external was retrieved. The
   23:31 preview row has no assistant session at all. S-404 and S-406 are
   internal only.

---

## Detection logic

**In plain English:**

- **Alert (per session):** a session that retrieved *external* content and
  then pointed output at a host outside `northwind-example.com`, either in a
  render event (blocked or allowed) or through the preview service. Set it to
  **High** if anything was allowed through or the preview service got a 200,
  otherwise **Medium**.
- **Hunt (per external item, daily):** an external item pulled in *by search*
  for **3 or more different users** in a day. That's a spraying candidate
  even if nothing has tried to leave yet.

Neither depends on the classifier, because on this sample it flagged
nothing.

**KQL (Microsoft Sentinel / Log Analytics, over fictional custom tables):**

```kql
// Ask Northwind: external content in context, then output pointing outside
// NorthwindLLMAudit_CL and NorthwindPreviewProxy_CL are FICTIONAL custom tables
let lookback = 1d;
let audit = NorthwindLLMAudit_CL | where TimeGenerated > ago(lookback);
let externalSessions = audit
    | where EventType == "retrieval" and Trust == "external"
    | summarize ExternalItems = make_set(Resource), Via = make_set(Via),
                UserUpn = take_any(UserUpn) by SessionId;
let renderEgress = audit
    | where EventType == "render"
    | where not(Resource == "northwind-example.com" or Resource endswith ".northwind-example.com")
    | project SessionId, Channel = "render", Outcome = Decision, Target = Resource;
let proxyEgress = NorthwindPreviewProxy_CL
    | where TimeGenerated > ago(lookback)
    | where SessionId != "-"
    | where not(TargetHost == "northwind-example.com" or TargetHost endswith ".northwind-example.com")
    | project SessionId, Channel = "proxy", Outcome = tostring(Status), Target = TargetHost;
union renderEgress, proxyEgress
| summarize Channels = make_set(Channel), Outcomes = make_set(Outcome),
            Targets = make_set(Target),
            Reached = countif(Outcome in ("allowed", "200")) by SessionId
| join kind=inner externalSessions on SessionId
| extend Severity = iff(Reached > 0, "High", "Medium")
| project SessionId, UserUpn, Severity, ExternalItems, Via, Channels, Outcomes, Targets
```

```kql
// Hunt: one external item retrieved by search for many different users
NorthwindLLMAudit_CL
| where TimeGenerated > ago(1d)
| where EventType == "retrieval" and Trust == "external" and Via == "search"
| summarize Users = dcount(UserUpn), UserList = make_set(UserUpn),
            Sessions = make_set(SessionId) by Resource
| where Users >= 3
```

On the sample, the alert returns **3 rows** (S-401 Medium, S-402 Medium,
S-403 High) and the hunt returns **1 row** (M-7781, 3 users). I ran the same
logic in Python over the 29 audit rows and 3 preview rows:

```
audit rows 29 sessions 7 users 6
Counter({'retrieval': 9, 'prompt': 7, 'response': 7, 'render': 4, 'shield': 2})
render Counter({'blocked': 3, 'allowed': 1})
external retrievals [('S-401', 'M-7781', 'search'), ('S-402', 'M-7781', 'search'), ('S-403', 'M-7781', 'search'), ('S-405', 'T-4520', 'user')]
proxy rows 3

Rule A
S-401 h.nguyen ext [('render', 'blocked', 'img.contoso-supplies.example')] -> ALERT Medium
S-402 p.dalton ext [('render', 'blocked', 'contoso-supplies.example')] -> ALERT Medium
S-403 m.ito ext [('render', 'allowed', 'img.contoso-supplies.example'), ('proxy', '200', 'img.contoso-supplies.example')] -> ALERT High
S-405 h.nguyen ext [] -> -
S-407 j.marsh - [('render', 'blocked', 'www.fabrikam.example')] -> -

Rule B
M-7781 ['h.nguyen', 'm.ito', 'p.dalton'] 3 -> HUNT
```

What it excludes: S-405 (external content, nothing pointed outside), S-407
(pointed outside, no external content), the 23:31 preview row (no assistant
session), and S-404 and S-406 (internal only). T-4520 is left out of the hunt
because it came in by `user`, and only once.

**If you run Microsoft 365 Copilot**, its audit records carry a real field
for this. Microsoft's
[Copilot audit log documentation](https://learn.microsoft.com/en-us/purview/audit-copilot)
says each `CopilotInteraction` record lists `AccessedResources`, and each
resource has an `XPIADetected` boolean for whether a cross-prompt injection
was detected from it. The Sentinel
[Microsoft Copilot connector](https://learn.microsoft.com/en-us/azure/sentinel/data-connectors-reference)
puts these records in the `CopilotActivity` table, with the parsed audit data
in the `LLMEventData` column:

```kql
// Real table: Copilot interactions where a resource was flagged as XPIA
CopilotActivity
| where TimeGenerated > ago(1d)
| where RecordType == "CopilotInteraction"
| mv-expand Res = LLMEventData.AccessedResources
| where tobool(Res.XPIADetected) == true
| project TimeGenerated, ActorName, AppHost,
          ResourceName = tostring(Res.Name), ResourceType = tostring(Res.Type),
          ResourceId = tostring(Res.ID)
```

Be clear about what that query can't do. EchoLeak's email was written to
*avoid* the XPIA classifier, so on the real attack this query would most
likely have returned nothing. Use it for the attacks that are caught, and
lean on the egress side (proxy, DNS and firewall logs for odd outbound
fetches) for the ones that aren't.

**What I verified and what I didn't.** Both Northwind tables, their columns,
the `Trust`/`Via` values and the preview service are invented. The real
parts: `AccessedResources`, `XPIADetected`, `RecordType` and `AppHost` come
from the Microsoft Learn audit page; the `CopilotActivity` table and its
`ActorName`, `AppHost`, `RecordType` and `LLMEventData` columns come from the
[table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/copilotactivity).
The `LLMEventData.AccessedResources` path is how Microsoft's own
[sample queries](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/copilotactivity)
read it, but those samples name the table `LLMActivity` rather than
`CopilotActivity`, so check which name your workspace has before saving the
query. `take_any`, `make_set`, `countif`, `dcount`, `mv-expand` and `union`
are standard KQL. None of the queries has been run against a live workspace,
only the Python equivalent of the first two.

**Tuning note:** the 1-day window and the threshold of 3 users are my
starting points, not published figures. The hunt will flag popular,
legitimate external items too, such as a supplier's price list everyone
asks about, so expect to keep a short reviewed list and to raise the
threshold for big shared mailboxes. Use exact host matching (`==` or
`endswith ".northwind-example.com"`), because a bare `endswith
"northwind-example.com"` also matches a lookalike such as
`notnorthwind-example.com`. The biggest blind spot: this only works because
Ask Northwind logs `Trust` and unwraps the preview URL. If your app logs
neither, the alert can't be built, and that's a logging requirement to raise
with the app team (Day 19 goes further). The real fix for S-403 isn't a
detection at all. It's stopping `preview.northwind-example.com` from fetching
arbitrary external URLs for the chat window.

---

## Your turn

1. Map each of the seven EchoLeak steps to the Northwind sample. Which steps
   can you see in the logs, which ones can't you, and which row shows each
   one you can?
2. S-401 and S-402 were blocked and S-403 wasn't. Explain exactly why, in
   terms of the allow-list, and write a one-paragraph change request to the
   team that owns `preview.northwind-example.com`.
3. The paper and Aim both suggest keeping external content out of answers
   about internal data. Pick two legitimate Ask Northwind requests this would
   break, and propose a rule that keeps one of them working without bringing
   back the S-403 path.
4. You're the analyst on shift when the High alert fires for S-403. List
   your first five actions in order, including who you'd notify and what you
   would need to recover from the preview service to judge what left.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Aim Labs (vendor research, now hosted by Cato Networks): [Breaking down 'EchoLeak', the first zero-click AI vulnerability enabling data exfiltration from Microsoft 365 Copilot](https://www.catonetworks.com/blog/breaking-down-echoleak/)
- Reddy and Gujral (AAAI Fall Symposium 2025): [EchoLeak: The First Real-World Zero-Click Prompt Injection Exploit in a Production LLM System](https://arxiv.org/abs/2509.10540)
- NIST NVD: [CVE-2025-32711](https://nvd.nist.gov/vuln/detail/cve-2025-32711)
- Microsoft MSRC: [How Microsoft defends against indirect prompt injection attacks](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)
- MITRE ATLAS: [AML.T0051.001 LLM Prompt Injection: Indirect](https://atlas.mitre.org/techniques/AML.T0051.001)
- Microsoft Learn: [Audit logs for Copilot and AI applications](https://learn.microsoft.com/en-us/purview/audit-copilot) · [CopilotActivity table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/copilotactivity) · [Sample queries for CopilotActivity](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/queries/copilotactivity)
- NCSC: [Prompt injection is not SQL injection (it may be worse)](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)
- This log: [ANALYSIS.md, section 2](../ANALYSIS.md#what-the-real-world-shows) (EchoLeak in context) · [Day 10](2026-11-12-owasp-llm-top-10.md) (the first indirect injection in Ask Northwind, ticket T-4471) · [Day 11](2026-11-13-direct-prompt-injection-vs-jailbreaking.md) (the direct version, and why the classifier is telemetry)

⬅️ [Learning log index](README.md) · ➡️ Day 13: Threat modelling agents: lethal trifecta and Rule of Two (15 Nov)
