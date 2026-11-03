# AI in Cybersecurity: What Actually Changed

**Three fronts, one lesson: stop trusting what a thing looks like, and control what it can do.**

*November 2026. This is the anchor piece for the daily [learning log](learning-log/README.md). Each section is expanded, with sample logs and detections, across the month.*

> **Evidence note.** The incidents here come from published reports, linked throughout.
> Nothing below is a private war story. Where a recommendation is judgement rather than a
> measured result, the wording says so, and any numeric threshold is a starting point to
> tune. Vendor research is labelled as vendor research.

---

## The short version

- **Deepfakes** have not created a new class of fraud. They remove the last doubt from an old one. Controls that authenticate the *transaction* hold up. Controls that ask a human to judge a face or voice are on borrowed time.
- **Prompt injection** is not a bug waiting for a patch. A language model has no reliable line between instructions and data, so assume it will be fooled and design so that being fooled does limited damage.
- **SOC AI** earns its keep on narrow, repetitive work with a checkable answer. Autonomy should be granted per action, based on reversibility and blast radius, never per "agent".

All three come down to the same thing. Language models and media generators are very good at producing plausible content, so plausibility has stopped being evidence of anything.

---

## 1. Deepfakes and next-generation social engineering

### Cutting through the hype

Start with the numbers, and be honest about what they can't show. The FBI's 2025 Internet Crime Report put **business email compromise at about US$3.05 billion**, with **a little over US$30 million tied to BEC with a confirmed AI component**, roughly 1% ([SecureWorld summary](https://www.secureworld.io/industry-news/ai-enabled-fraud-topped-893m-fbi)). That figure is a floor, because it only counts AI use the victim noticed and reported. A convincing fake is exactly the kind a victim doesn't report as a fake.

Two wrong conclusions are available. "Only 1%, ignore it" misses the severity of individual cases and the attribution gap. "Deepfakes are everywhere" has no evidence behind it. A fairer reading: most BEC money still moves because of plain text, a compromised mailbox or a changed bank account, and AI is an amplifier for the high-value, high-effort end.

### How it is actually used

The public cases share a pattern that the "real-time digital twin" narrative misses.

| Case | What the fake did | What stopped it, or didn't |
|---|---|---|
| **Arup, 2024** | A staff member doubted a "confidential transaction" email. A video call with apparent senior colleagues removed the doubt. Result: [15 payments to 5 accounts, about US$25m](https://www.bankinfosecurity.com/fraudsters-deepfake-entire-meeting-swindle-255m-a-24273) | Nothing technical. The fraud surfaced [after a follow-up with UK headquarters](https://insurancebusinessmag.com/uk/news/cyber/deepfake-video-conference-sees-criminals-escape-with-us25-million-489790.aspx) |
| **Ferrari, 2024** | WhatsApp messages, then a [cloned-voice call from a new number](https://fortune.com/2024/07/27/ferrari-deepfake-attempt-scammer-security-question-ceo-benedetto-vigna-cybersecurity-ai) about a confidential deal | An executive asked about a book the CEO had recently recommended. The call ended |
| **LastPass, 2024** | [Calls, texts and a deepfake voicemail](https://blog.lastpass.com/posts/attempted-audio-deepfake-call-targets-lastpass-employee) posing as the CEO on WhatsApp | The employee noticed an unusual channel and urgency, ignored it and reported it |

Three lessons follow.

**The deepfake is an objection handler, not the attack.** In the Arup case the pretext began with an email, and the video existed to answer the victim's doubt. The attack is still a pretext, urgency, secrecy and a payment rail.

**The sophistication is often lower than reported.** The Hong Kong superintendent said he [believed the fraudster downloaded existing videos and added AI voices](https://www.bankinfosecurity.com/fraudsters-deepfake-entire-meeting-swindle-255m-a-24273). That's his stated belief rather than a confirmed finding, and it's a long way from a fully interactive synthetic boardroom. Assume real-time capability exists and is improving, but don't let that distract from the cheaper version that already works.

**Channel change is the most reliable tell.** Ferrari and LastPass both involved a new number or an out-of-policy channel. The attacker chooses the channel because your controls don't live there.

### The other front: the help desk

The most damaging voice attacks of the last few years didn't need a clone. The [CISA and FBI advisory on Scattered Spider](https://www.ic3.gov/CSA/2025/250729.pdf) describes actors who pose as employees to get help desks to reset passwords and move MFA to a device they control, often [over several calls](https://www.ic3.gov/CSA/2025/250729.pdf) that first learn the reset procedure. A good voice clone is a nice extra here. Knowing the procedure and sounding plausible is usually enough.

That makes the reset path the soft underbelly of the identity programme. You can spend years on phishing-resistant MFA and leave a phone line that swaps it for a new device after a few answers from LinkedIn. It's also worth noticing a gap: the advisory's mitigations cover phishing-resistant MFA and training, but say little about *how* a help desk should verify a caller. You have to design that yourself.

### What actually stops these attacks

The rule: **verify the request through a path the attacker didn't choose, and make the system enforce it.** Do not authenticate the media. Authenticate the transaction.

| Control | How to do it properly | How it fails in practice |
|---|---|---|
| **Call-back from a system of record** | The verifier hangs up and calls a number from the HR directory or vendor master, never one from the message | Staff use the number in the email signature. A new-starter directory is out of date |
| **Dual control enforced in the bank or ERP portal** | Preparer and approver are separate logins, and the portal won't release without both | It lives in policy but not in the tool. The approver "just approves" because the preparer said the CFO confirmed |
| **Vendor bank-change process** | Any bank detail change triggers a call to a known contact, plus a hold on the first payment | Changes arrive by email and get keyed in the same day |
| **Payee name matching** | Use [Confirmation of Payee](https://www.ausbanking.org.au/scam-safe-accord/confirmation-of-payee/) results as a stop-and-check step | It's [advisory rather than a block](https://www.ausbanking.org.au/scam-safe-accord/confirmation-of-payee/), domestic only, and legitimate mismatches teach people to click through |
| **No-exceptions rule from the top** | The CEO and CFO state publicly that nobody will ever be asked to skip verification, whatever the deal | An executive actually does ask for an exception, and the training is undone in one afternoon |
| **Signed approvals** | High-value approvals happen in a workflow the approver reaches with phishing-resistant sign-in, so the record is the authorisation and a call is only context | A side channel stays open for "urgent" items |
| **Help desk verification ladder** | Prefer proof from an existing strong credential. Otherwise use manager confirmation via a directory call-back, or a [verified ID flow](https://learn.microsoft.com/en-us/entra/verified-id/helpdesk-with-verified-id). Issue a short-lived bootstrap, not a password read over the phone | Staff are measured on call time. A caller with a sad story gets a shortcut |
| **Restrict the recovery aftermath** | Alert on new authentication methods. Hold sensitive access for a period after a change (judgement call, 24 hours is a sensible start) | Nobody watches the event, or the hold is removed after one complaint |
| **Phishing-resistant authentication** | FIDO2/WebAuthn or PKI. Under [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), AAL3 requires phishing resistance and doesn't allow syncable authenticators, while AAL2 must at least offer a phishing-resistant option | See below |
| **Limit inbound contact** | Allow-list external collaboration tenants instead of open federation | Business units request broad exceptions, and personal WhatsApp stays outside it anyway |

Be clear about what phishing-resistant MFA does and doesn't do. It's the single best investment against the help desk and adversary-in-the-middle route, because origin binding means a stolen code or relayed session prompt doesn't work, so long as the recovery path is equally strong. **It does nothing for an Arup.** That employee used a legitimate account on a legitimate session and authorised the payments himself. Identity controls protect accounts. Only business-process controls protect a persuaded human.

### What not to rely on

**Spotting artefacts.** Ferrari's executive did notice something off in the voice. That's luck worth having, not a control. "Listen for robotic speech" is training with a shelf life.

**Deepfake detection as a gate.** The [Deepfake-Eval-2024 benchmark](https://arxiv.org/html/2503.02857v4) found open-source detectors lost about 50% of their AUC on real-world video, 48% on audio and 45% on images, compared with their original benchmarks. The best commercial tools did better, but none reached 90% accuracy, and the authors note a caveat on how the audio set was labelled. Compression on a real call makes this harder, not easier. Use detection as a signal that can raise suspicion. Never let a "real" verdict lower it.

**Shared secrets and safe words, at scale.** They suit a small executive team, and Ferrari's ad hoc question worked. They break down across thousands of staff, they leak, and anything discoverable online is no secret. A question should be recent and private, and even then it's a backstop.

**Video ID for recovery on its own.** [NIST's Revision 4](https://pages.nist.gov/800-63-4) added controls for injection attacks and forged media because remote proofing is now a target. "Show your licence on camera" needs liveness and injection defences behind it, or it's just another piece of media to fake.

---

## 2. LLM vulnerabilities and prompt injection

### The framing that matters

The UK NCSC put it best: prompt injection [is not SQL injection](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection), and treating it that way is dangerous. SQL injection has a real fix because parameterised queries separate code from data. A language model has no such separation. The NCSC calls it an "inherently confusable deputy" and says that if a system can't tolerate the remaining risk, it may not be a good use case for LLMs.

Three terms get mixed up, and the mix-up wastes budget:

| Term | What it is | Who suffers | Primary defence |
|---|---|---|---|
| **Jailbreaking** | Talking a model out of its content rules | Usually a safety, brand or abuse problem | Model-level safety, abuse monitoring |
| **Direct injection** | A user overrides the app's instructions in their own session | Limited by that user's own rights, *if* the app's tools enforce them | Never put secrets or authorisation in the prompt |
| **Indirect injection** | Instructions hidden in content the model reads for someone else, such as an email, web page, ticket or log line | The victim, using the victim's access | Architecture |

Indirect injection is the serious one, because the attacker never needs an account on your system.

### What the real world shows

**EchoLeak ([CVE-2025-32711](https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html), CVSS 9.3)** is the reference case. An email with hidden instructions could lead Microsoft 365 Copilot to mix untrusted content with internal data and leak it through trusted Teams and SharePoint URLs, with no click from the user. Microsoft fixed it server-side, and there was no evidence of malicious use. The important part is the chain: researchers [got past the injection classifier](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability), then used a rendering path to get data out. No single control was going to hold.

**Activity in the wild is real, but scrappier than the research.** Google's crawl of the public web [found the malicious category up 32% between November 2025 and February 2026](https://blog.google/security/prompt-injections-web/), with low overall sophistication, plenty of pranks and SEO abuse, and little sign of the advanced research techniques. Its scope excludes most social media and log-in walled content, so it's a partial view. Other 2026 reporting [collected by the Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-indirect-prompt-injection-in-the-wild-2026/) describes hidden payloads aimed at coding agents, ad-review bypass, and Noma's GrafanaGhost research, where poisoned log entries steered an assistant during log summarisation. It also notes agent flaws paid through bug bounties without a CVE, so public vulnerability counts undercount this category.

Reasonable reading: today's attackers are mostly noisy and opportunistic, but the method is proven and the target set is growing every time an agent gets a new tool.

### Start with blast radius

Two simple models do most of the threat-modelling work.

- **[The lethal trifecta](https://simonw.substack.com/p/the-lethal-trifecta-for-ai-agents)** (Simon Willison): private data, untrusted content, and a way to communicate externally. All three together allow theft.
- **[The Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)** (Meta): in one session, an agent should have at most two of [A] process untrustworthy input, [B] access sensitive data or systems, [C] change state or communicate externally. If it needs all three, it needs human approval or another reliable validation.

Run this on every agent before you buy a single guardrail. Many agents can lose a leg with little loss of value: a summariser doesn't need to send anything, and a public web researcher doesn't need your SharePoint.

### A pragmatic architecture

Think in layers, ordered by how much you can actually rely on each.

**Layer 1: deterministic limits (rely on these).**
- Permissions come from the *end user's* identity at the tool, never a shared super-account for the agent.
- Apply the NCSC principle: [when an LLM processes data from a party, its privileges drop to that party's](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection). If it's reading an external email, privileged tools are off for that step.
- Egress allow-lists at network level for anything that can make requests.
- Tool arguments checked against schemas and allow-lists in ordinary code.

**Layer 2: isolate untrusted data from planning (strong, with a cost).** Designs such as [CaMeL](https://arxiv.org/pdf/2503.18813) use a privileged model that sees only the trusted request and writes the plan, a quarantined model that parses untrusted data with no tools, and an interpreter that tracks data flow and checks policy before each tool call. It solved 77% of AgentDojo tasks with provable security, against 84% undefended, and used roughly 2.8 times the tokens. The authors state plainly that prompt injection isn't fully solved: a planted fact can still corrupt a summary, policies have to be written and kept up, and frequent approvals cause fatigue. Most teams won't build this. The cheap version is still valuable: extract untrusted content into strict typed fields before it goes near anything with tools.

**Layer 3: output handling (mandatory, frequently forgotten).** Treat model output as untrusted input to whatever comes next.
- Strip or proxy remote images, and allow-list link domains. Markdown image rendering keeps turning up as the exit in published chains.
- Parameterise SQL, escape HTML and never pass output to a shell.
- Validate against a schema, and reject rather than repair.
- Show approvers the *actual arguments* of a tool call, not the model's description of what it's about to do.

**Layer 4: input hygiene (useful, not a boundary).** Normalise Unicode, remove zero-width characters, strip HTML comments, hidden text, document metadata and speaker notes, and cap length. This removes the cheapest tricks and makes logs readable. It doesn't address a plainly worded instruction in a normal sentence, and the NCSC specifically warns off deny-lists because rewording is endless.

**Layer 5: probabilistic guardrails (telemetry first).** Classifiers and "firewalls for AI" catch commodity attacks and generate useful signal. Don't mistake that for a boundary. [The Attacker Moves Second](https://arxiv.org/html/2510.09023v1) took 12 defences, most of which had reported near-zero attack success, and broke most of them above 90% using adaptive attacks. Spotlighting and prompt sandwiching went from as low as 1% on static attacks to above 95%. Commercial detectors were among those above 90%.

**Layer 6: monitoring.** Log prompts, retrieved document IDs, tool calls with arguments, and refusals. The NCSC points out that failed tool calls can reveal an attack in its early stages. Full prompt logging brings its own privacy and retention problem, so settle that with legal before launch rather than after an incident.

### Data poisoning: keep the threat model honest

Separate three things.

**Training poisoning.** The [Anthropic, UK AISI and Alan Turing Institute study](https://www.anthropic.com/research/small-samples-poison) reliably backdoored models from 600M to 13B parameters with 250 documents, about 0.00016% of tokens, showing that absolute count mattered rather than share. Read the limits too: the backdoor produced gibberish on a trigger, the authors say that's unlikely to be a significant risk in frontier models, and larger models and more complex behaviour are open questions. If you fine-tune on scraped data, take it seriously. If you consume a major hosted model, this isn't your first problem.

**Retrieval poisoning, which is probably your first problem.** [PoisonedRAG](https://arxiv.org/abs/2402.07867v2) reached a 90% success rate by adding five malicious texts per target question to a knowledge base of millions of entries. In a company, the realistic form needs no research lab: anyone who can edit the wiki, share a SharePoint file, raise a ticket or send a mail to an indexed mailbox can write into the model's context. **The write permissions on your knowledge sources are now part of your prompt security.**

Controls: enforce the source's ACLs at retrieval time, carry provenance and a trust tier with every chunk, separate externally writable sources from curated ones, and make it possible to purge a source and rebuild the index quickly.

**Agent memory and supply chain.** Persistent memory lets one injection survive past its session, so treat memory writes as privileged and reviewable. For models, pin versions and hashes, prefer safe serialisation formats such as safetensors, and vet third-party tools and MCP servers as you would any code running with your credentials.

### Where current tools still fail

- **Plain language.** Injection doesn't need a special syntax, so there's no signature to find.
- **Adaptive attackers.** Static benchmark scores say little about resistance to someone tuning against your defence.
- **Text-only harm.** A poisoned summary that misleads a human triggers no tool call and no data-flow policy.
- **Approval fatigue.** Human-in-the-loop decays into a click. Few approvals, carrying real detail, beat many vague ones.
- **Non-English and multi-turn attacks.** Coverage tends to be weaker than the headline numbers.
- **Evaluation debt.** Teams test at launch, and then the model, prompts and tools all change.

Be wary of anything claiming to "stop" prompt injection. The [NCSC says the same](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection). Keep a regression suite and give someone time to attack each release with knowledge of the defences.

---

## 3. Autonomous security agents and AI defence

### What the evidence supports

The honest evidence base is thin, and much of it comes from vendors, so read it carefully.

| Source | Finding | Read it with |
|---|---|---|
| [Microsoft, live SOC telemetry](https://arxiv.org/html/2411.03116v2) | 30.13% lower mean time to resolution three months after Security Copilot adoption | Vendor authors, observational, and month 1 and 2 results weren't significant. Only incidents resolved within 12 hours were counted, and buyers may differ from non-buyers |
| [Phishing Triage Agent RCT](https://www.arxiv.org/abs/2511.13860) | Up to 6.5 times more true positives per analyst minute, 77% better verdict accuracy | A narrow, well-defined task. That's the point |
| [2026 SANS AI Survey](https://www.kiteworks.com/cybersecurity-risk-management/2026-sans-ai-survey-human-analyst/) (536 respondents, via secondary reporting) | 63% saw significant shortcomings in AI detection or response. About two-thirds had been misled by AI guidance at least once in a year, 9% more than 20 times | Self-reported |

The pattern matters more than the numbers. **AI works best on bounded tasks with a checkable answer**: reported-phishing triage, enrichment, writing a first query, drafting a ticket, building a timeline. It gets weaker as the work becomes grey and depends on undocumented context, such as knowing that this contractor always logs in from there, or that finance runs an odd script at quarter end. [Kaspersky's review](https://kaspersky.com/blog/autonomous-soc-2026-challenges-and-solutions/) of the autonomous SOC makes the same case: data quality, missing business context and analyst trust are the real limits.

### ML detection and the arithmetic of alert fatigue

No model escapes the base rate. Say an AI-powered IDS scores 10 million events a day, 1 in 100,000 is malicious, it catches 99% of them, and it wrongly flags just 0.1% of benign events.

| | Count |
|---|---|
| Malicious events | 100 |
| True positives (99%) | 99 |
| False positives (0.1%) | about 10,000 |
| **Precision** | **under 1%: one real alert in about 100** |

A demo that says "99% accurate" can produce that queue. Ask vendors for precision on *your* traffic, at your base rate. Then expect drift: migrations, acquisitions and new software all shift behavioural baselines, and anomaly detection reports "different", which isn't the same as "bad".

**The fatigue doesn't vanish, it moves.** Good AI triage shrinks the queue, and the risk changes from noise you can see to false negatives you can't. An auto-closed true positive leaves no trace unless you go looking. So:

- Sample auto-closed alerts for human QA every week.
- Seed known-bad test activity and confirm it gets escalated.
- Track the *overturn rate*, how often humans reverse the AI, by alert type.
- Protect junior analyst development, since triage is how people learn what normal looks like.

### Hallucination risk in playbooks

In a SOC, a hallucination rarely looks absurd. It looks like a plausible event ID, a field that doesn't exist, a confident statement in a ticket. The worst version is quiet:

1. The copilot writes a query with a wrong field name or table.
2. The query runs and returns zero rows.
3. The summary says "no evidence of lateral movement".
4. The incident is closed on an absence that was only ever a typo.

Attackers run into this too. Anthropic's report on an AI-orchestrated espionage campaign says the model [frequently overstated findings and occasionally fabricated data](https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf), including credentials that didn't work, which forced the operators to validate results. If it slows down people with every incentive to believe it, it should slow you down too.

Practical controls:

- **Evidence or it didn't happen.** Every factual statement in an AI summary links to a query and result. No link, no claim.
- **Separate "clean" from "no data".** Zero rows should trigger a check that the table has recent data and the fields exist, before anyone says "nothing found".
- **Validate generated artefacts.** Compile queries, lint rules and test them against sample data before they're trusted. A KQL query that compiles can still be wrong, so test with a known positive.
- **Retrieve, don't invent.** Playbook steps should come from your approved runbooks, with the model selecting and filling in, not composing response procedures from memory.

### Your SOC agent is an LLM deployment too

Everything in section 2 applies. A SOC agent reads attacker-controlled strings all day: command lines, file names, user agents, email subjects, DNS names. It has sensitive data and often tools. That's the lethal trifecta by default. GrafanaGhost-style log injection is a preview of an attacker writing to your analyst's assistant. Treat log fields as data, delimit and type them, keep the triage step that reads them away from containment tools, and require a separate confirmation from telemetry before any action.

### The line on autonomous containment

"Should the agent have containment rights?" is the wrong question. Ask it per action, and score each action on three things: **how reversible is it, how big is the blast radius, and what happens if it's wrong?**

A reasonable starting position, to be adjusted to your risk appetite:

| Action | Reversible? | Blast radius | Suggested starting level |
|---|---|---|---|
| Enrich, query, draft a ticket | Yes | None | Autonomous |
| Revoke sessions for one standard user | Yes | One user, minor pain | Autonomous on high-confidence detections |
| Isolate one standard workstation | Yes | One user | Autonomous with corroboration from a second signal |
| Disable a standard user | Yes | One user | Autonomous for narrow, tested detections, otherwise approve |
| Purge email across mailboxes | Partly | Many users | Human approval |
| Block a domain or IP organisation-wide | Yes, but outages happen quickly | Potentially everyone | Human approval |
| Disable a service account | Often not cleanly | Unknown dependencies | Human approval with an owner check |
| Isolate a server or production system | Technically | Business outage | Human decision, with a named owner |
| Touch a domain controller or identity provider | Risky | Whole company | Human only |

The best existing benchmark isn't an LLM. [Microsoft's automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption) is a useful pattern to study: a small set of containment actions, a claimed confidence of 99% or higher (Microsoft's figure), new detectors validated in audit mode first, undo for every action, and [exclusions](https://learn.microsoft.com/en-us/defender-xdr/automatic-attack-disruption-exclusions) for assets that shouldn't be touched automatically. The lesson is that autonomy is safest when it's narrow, tested and reversible. It isn't a chatbot with an API key.

Design rules that follow:

- **The model recommends, code executes.** Isolation runs through a fixed, tested function with its own policy checks. The model never holds a broad admin token.
- **Assume the attacker can trigger your automation.** If forged signals can get the CEO's laptop isolated or the payroll server cut off, your defence is now their denial-of-service tool. Rate-limit actions, protect critical assets by policy, and include a kill switch that someone has actually tested.
- **Give the agent its own identity.** Least privilege, time-boxed access, and full logging, so that its actions are distinguishable from a person's.
- **Name a human owner.** "The agent did it" won't satisfy a regulator, a customer or your own post-incident review.
- **Earn each level.** Move each action through shadow, recommend, approve, then automatic with rollback, on measured results. Demote it just as readily after a bad miss.

There's a genuine trade-off in all this. Human approval is safer and also slower, and fast attacks don't wait. Reversibility is what resolves it: if an action can be undone in minutes, you can accept more false positives in exchange for speed. If it can't, you pay for the delay.

Measure overturn rate per action, time to undo, business impact of wrong actions, and missed escalations. Mean time to respond on its own rewards exactly the recklessness you're trying to avoid.

---

## If you only have a quarter

**Fraud and identity**
1. Make dual control a system setting in the bank portal and ERP, and add a first-payment hold on changed bank details.
2. Rewrite the help desk reset procedure, and test it with a realistic vishing exercise.
3. Roll out phishing-resistant authentication for admins and finance, then alert on every new authentication method.

**LLM deployments**
4. Run the Rule of Two across every agent, and remove one leg wherever you can.
5. Strip remote images, enforce egress allow-lists and use per-user permissions at the tool layer.
6. Stand up logging and an adaptive red-team routine before you buy another guardrail.

**SOC**
7. Start with phishing triage and enrichment, with evidence links required.
8. Add QA sampling of auto-closed alerts and seeded test cases.
9. Write the autonomy table above for your organisation, get it signed off, and promote one action at a time.

---

## Further reading

The whole month goes deeper on each of these: see the [28-day plan](learning-log/README.md).

- NCSC: [Prompt injection is not SQL injection (it may be worse)](https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection)
- Meta: [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)
- NIST: [SP 800-63-4 Digital Identity Guidelines](https://pages.nist.gov/800-63-4)
- CISA and partners: [Scattered Spider advisory](https://www.ic3.gov/CSA/2025/250729.pdf)
- Nasr et al.: [The Attacker Moves Second](https://arxiv.org/html/2510.09023v1)
- Debenedetti et al.: [Defeating Prompt Injections by Design (CaMeL)](https://arxiv.org/pdf/2503.18813)
