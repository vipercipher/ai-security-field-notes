# Day 26 — Guardrails for SOC Agents: Identity, Rollback and Kill Switches

📅 28 November 2026 · 🏷️AI in the SOC · ⏱️ ~30 min

---

## Why it matters

Day 25 decided *which* actions Northwind's SOC agent may take on its
own. Today is about what sits underneath that policy: the account the
agent acts with, the way each action gets undone, and the switch that
stops the whole thing when it goes wrong.

ANALYSIS.md gives three design rules that only work if this plumbing
exists: "give the agent its own identity", "rate-limit actions, protect
critical assets by policy, and include a kill switch that someone has
actually tested", and "move each action through shadow, recommend,
approve, then automatic with rollback". Each sounds like a checkbox.
Each turns out to have a catch once you look at how tokens, logs and
undo actually work in Microsoft Entra and Graph. The biggest one: when
you disable the agent's identity, it doesn't necessarily stop straight
away.

---

## The concept

### 1. Its own identity, and nothing borrowed

If the agent acts through an analyst's account or a shared admin
account, its actions look exactly like that person's. You can't scope
it, you can't kill it without locking out a human, and your logs can't
tell you which actions the model chose.

The joint guidance from CISA, the Australian Signals Directorate's ACSC
and partners
([*Careful adoption of agentic AI services*](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services))
is direct about it:

| What the guidance says | What it means for a SOC agent |
|---|---|
| "construct each agent as a distinct principal, a cryptographically anchored identity with its own unique keys or certificates" | One identity per agent, authenticated with a certificate or federated credential rather than a shared password |
| Secrets get stolen "when organisations keep them static, share them across multiple agents, or protect them poorly" | A forgotten test secret on the agent's app registration is a backdoor with the agent's permissions |
| "Prohibit agents from modifying their own privileges" | The agent must not be able to add credentials or roles to itself |
| "Require just-in-time credentials for high-impact or privileged actions" | Standing permission for routine actions, short-lived elevation for the rest |
| "By executing actions under a trusted agent identity, the system produces audit logs that appear legitimate and delay detection" | A stolen agent identity looks like the agent doing its job, so you need to know what "its job" looks like in the logs |

In Microsoft's world there are two ways to give an agent its own
identity:

| Option | What it is | Things to know |
|---|---|---|
| **App registration and service principal** | The long-standing way to give software an identity in Entra ID | Works everywhere. Conditional Access for service principals needs Workload Identities Premium licences ([Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload)) |
| **[Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id)** | An identity type built for AI agents. Each agent identity is created from a blueprint and can have a **sponsor**, "the human user or group that's accountable for an agent" ([agent identities](https://learn.microsoft.com/en-us/entra/agent-id/agent-identities)) | Microsoft says Agent ID "is available for all Microsoft Entra customers", but extending Entra security features to agents "requires Microsoft Agent 365", a separate licence. The sponsor field is a direct answer to ANALYSIS.md's "name a human owner" |

Either works. My judgement is that the choice matters less than the
habits: one identity per agent, certificates not secrets, the smallest
set of Graph permissions that does the job, and an owner who reviews it.

A useful detail for later: the
[`MicrosoftGraphActivityLogs`](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)
table records `ClientAuthMethod` for every request: 0 for a public
client, **1 for a client ID and secret, 2 for a client certificate**. If
the agent is supposed to use a certificate, any request with a 1 is
either a misconfiguration or someone else.

### 2. Rollback is designed in, not bolted on

Day 25 showed that "reversible" isn't the same as "free". The other half
is that undo only exists if someone built it before the action ran. For
every action the agent can take, write down what it changes, what state
to record first, and what undo really means:

| Action (Graph call) | Record before acting | Undo | What undo can't give back |
|---|---|---|---|
| Revoke sessions (`POST /users/{id}/revokeSignInSessions`) | Nothing to restore | None. The user signs in again | Unsaved work. Microsoft also notes "a small delay of a few minutes before tokens are revoked" ([Graph reference](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)), so it isn't instant either |
| Disable user (`PATCH /users/{id}` setting `accountEnabled`) | The account's current `accountEnabled` value, and why | Set it back to the **recorded** value | Anything that ran as that account and failed meanwhile (Day 25's `svc-backup`) |
| Isolate device (Defender API, not Graph) | Device ID and isolation type | Release from isolation | Day 25's caveats: proxies, offline devices, delayed enforcement |

The "record before acting" column is where rollback goes wrong. An undo
that blindly sets `accountEnabled` to `true` will cheerfully re-enable an
account that HR disabled last week. Rollback means restoring the
*previous* state, so the action function has to capture it first.

There's also a second kind of rollback. The CISA guidance asks for
"versioning and rollback mechanisms to safely revert a system to
known-good agent behaviours", and for using "continuous evaluation to
determine when to expand system scope or when to roll back autonomy and
access in response to failures". That's rolling back the *agent*: its
model, prompt, tools or autonomy level. It's the demotion rule from
Day 25's last exercise, and it needs the same thing as action rollback:
a recorded known-good version to go back to.

### 3. Kill switches come in layers

A kill switch is a way to stop the agent acting, fast, without needing
the agent's cooperation. OWASP's
[Top 10 for Agentic Applications 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/)
lists Rogue Agents (ASI10) as "malicious or compromised AI Agents that
deviate" from their intended behaviour. The kill switch is what you
reach for when you think you have one, and it's also what you reach for
when the agent is simply misbehaving at 3 am.

No single switch does the whole job:

| Layer | What it stops | How fast | What it misses |
|---|---|---|---|
| **Pause flag in the orchestrator** | New tasks | Seconds | Work already in flight, unless every worker checks the flag before *every* action, not just at the start of a task. Useless if the orchestrator itself is the problem |
| **Circuit breaker in the action function** (Day 25's `isolate_device()` and friends) | Every write that goes through the policy layer | Seconds | Anything that reaches the API without going through the function, including a stolen credential |
| **Disable the agent's identity** | New tokens from Entra ID | Seconds for new sign-ins | Access tokens already issued (see below) |
| **Remove credentials and permissions** | Everything, eventually | Slow to apply and slow to restore | Nothing, which is why it's the last resort |

The catch is the third row. An access token is valid until it expires,
and Microsoft gives access tokens "a random value ranging between 60-90
minutes" by default
([access tokens](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)).
Disabling a service principal stops it getting a *new* token. A token
issued before the disable can keep working until it expires, unless
something revokes it.

That something is
[continuous access evaluation (CAE) for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload).
With CAE, when a service principal is disabled, deleted or flagged as
high risk, "the resource provider rejects the token and returns a `401`
response with a claims challenge". The limits, all from the same page:

- It only works for requests to **Microsoft Graph**. Other APIs, such as
  the Defender endpoint API that isolates devices, aren't covered.
- It only works for single-tenant service principals. **Managed
  identities aren't supported.**
- The app has to opt in by declaring the `cp1` client capability. "An
  application won't receive claims challenges and won't receive CAE
  tokens unless it explicitly declares the `cp1` capability."
- In exchange, CAE tokens for workload identities are long-lived, "up to
  24 hours".

That last point is a real trade-off. CAE makes the identity kill switch
close to instant for Graph, but if revocation fails for any reason
you're holding a token that lasts a day instead of an hour. Without CAE,
the identity switch takes up to 90 minutes to fully bite, which is why
the orchestrator and action-function layers have to stop the agent
first.

Two more design points, both my judgement:

- **Pulling the switch shouldn't need permission.** The on-call analyst
  should be able to pause the agent without finding its owner. Restarting
  it is the step that needs sign-off.
- **The switch is a target too.** Someone who can pause your agent can
  switch off your containment before they act. Restrict who can pull
  it, log every pull, and alert on it.

---

## Sample logs

Everything is fictional. Northwind's SOC agent has its own service
principal, `nw-soc-agent` (AppId `4f6d2c1e-9a7b-4c3d-8e2f-1a2b3c4d5e6f`,
object ID `9d8c7b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d`; both made up). It's
meant to authenticate with a certificate, only from the orchestrator's
egress address `198.51.100.20`, and only to read users, revoke sessions
and disable users through Graph.

On Friday 27 November the SOC ran a kill switch drill at 14:00 AEDT
(03:00 UTC). The drill notes say the pause flag was set at 03:00:00 UTC
and the service principal was disabled at 03:00:40 UTC. The agent's
client doesn't declare `cp1`.

The extract below is from **`MicrosoftGraphActivityLogs`, a real
Microsoft table**, showing only rows where `AppId` is the agent's, and
only some of the columns. Times in UTC; Northwind is on AEDT (UTC+11).

```
TimeGenerated         IPAddress      ClientAuthMethod  RequestMethod  RequestUri                                                                                  ResponseStatusCode  TokenIssuedAt
2026-11-26T12:45:10Z  198.51.100.20  2                 GET            https://graph.microsoft.com/v1.0/users/a.chen@northwind-example.com?$select=accountEnabled,department    200                 2026-11-26T12:20:02Z
2026-11-26T21:58:03Z  198.51.100.20  2                 GET            https://graph.microsoft.com/v1.0/users/m.lee@northwind-example.com?$select=accountEnabled,department     200                 2026-11-26T21:40:11Z
2026-11-26T21:58:05Z  198.51.100.20  2                 POST           https://graph.microsoft.com/v1.0/users/m.lee@northwind-example.com/revokeSignInSessions                  200                 2026-11-26T21:40:11Z
2026-11-26T22:15:44Z  203.0.113.77   1                 GET            https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName                          200                 2026-11-26T22:15:40Z
2026-11-26T22:16:02Z  203.0.113.77   1                 POST           https://graph.microsoft.com/v1.0/servicePrincipals/9d8c7b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d/addPassword      403                 2026-11-26T22:15:40Z
2026-11-26T22:16:30Z  203.0.113.77   1                 GET            https://graph.microsoft.com/v1.0/users/m.lee@northwind-example.com                                       200                 2026-11-26T22:15:40Z
2026-11-27T02:41:20Z  198.51.100.20  2                 GET            https://graph.microsoft.com/v1.0/users/j.patel@northwind-example.com?$select=accountEnabled,department   200                 2026-11-27T02:41:15Z
2026-11-27T02:59:47Z  198.51.100.20  2                 GET            https://graph.microsoft.com/v1.0/users/r.singh@northwind-example.com?$select=accountEnabled,department   200                 2026-11-27T02:41:15Z
2026-11-27T03:01:12Z  198.51.100.20  2                 PATCH          https://graph.microsoft.com/v1.0/users/r.singh@northwind-example.com                                     204                 2026-11-27T02:41:15Z
2026-11-27T03:01:30Z  198.51.100.20  2                 GET            https://graph.microsoft.com/v1.0/users/r.singh@northwind-example.com?$select=accountEnabled             200                 2026-11-27T02:41:15Z
```

The first row is from Thursday evening in Sydney (23:45 AEDT) and sits
outside today's review window. Later, the SOC found a client secret on
the agent's app registration that had been created for testing and
never removed.

---

## What to look for

1. **Count the rows.** 10 rows, 9 of them on Friday in Sydney. Of those
   9, 4 are the agent doing exactly what it should: from the orchestrator,
   with a certificate, on allowed operations, before the drill.
2. **Three requests from the wrong place, with the wrong credential.**
   At 22:15 to 22:16 UTC (09:15 AEDT), 3 requests came from
   `203.0.113.77` with `ClientAuthMethod` 1, a client secret. The agent
   never uses a secret. Someone has the forgotten test secret.
3. **They went for persistence first.** The caller listed service
   principals, then tried `addPassword` on the agent's own service
   principal, which adds a new secret to it. That's
   [ATT&CK T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/):
   "Adversaries may add adversary-controlled credentials to a cloud
   account to maintain persistent access". It returned **403**, because
   the agent has no permission to manage applications. Least privilege
   did its job. The `servicePrincipals` listing returned 200, which says
   the agent has a broader read permission than it needs, so that's
   worth checking.
4. **The read that worked.** The third request read `m.lee`'s profile
   and got a 200. It's an operation the agent is allowed to do, so an
   allowlist alone would pass it. Only the IP and the credential type
   give it away. This is what CISA means by audit logs that "appear
   legitimate".
5. **The kill switch didn't stop the in-flight task.** The agent read
   `r.singh` at 02:59:47, 13 seconds before the pause. At 03:01:12, after
   the pause *and* after the service principal was disabled, it sent a
   `PATCH` to `r.singh` and got **204 No Content**, which is how Graph
   reports a successful update. It then read the account back at
   03:01:30. Two lessons in one row: the worker only checked the pause
   flag when it picked up the task, and the token issued at 02:41:15
   was still accepted 19 minutes later because the client doesn't use
   CAE. That token could stay valid until somewhere between 03:41 and
   04:11 UTC.
6. **Not every change shows here.** Device isolation goes through the
   Defender API, not Graph, so it would never appear in this table. The
   drill only proves the kill switch for the actions you looked at.

---

## Detection logic

**In plain English.**

- Look at every Graph request made by the SOC agent's AppId on the
  previous day in Sydney time.
- Flag a request if any of these is true:
  - **Unexpected IP:** it didn't come from the orchestrator's egress
    address.
  - **Not certificate auth:** `ClientAuthMethod` isn't 2.
  - **Not allowlisted:** the method and path aren't one of the three
    operations the agent is meant to perform.
  - **After the kill switch:** it succeeded (2xx) after the switch was
    pulled.
- Show how old the token was when it was used, to see whether
  revocation is working.

**KQL (Microsoft Sentinel).** `MicrosoftGraphActivityLogs` and its
columns are real
([table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs)).
The AppId, IP and kill time are Northwind's fictional values.

```kql
// Graph calls by Northwind's SOC agent that break its identity guardrails
let agentAppId = "4f6d2c1e-9a7b-4c3d-8e2f-1a2b3c4d5e6f";   // fictional
let orchestratorEgress = dynamic(["198.51.100.20/32"]);
let dayStart = datetime(2026-11-26T13:00:00Z);   // Fri 27 Nov 00:00 AEDT
let dayEnd   = datetime(2026-11-27T13:00:00Z);   // Sat 28 Nov 00:00 AEDT
let killTime = datetime(2026-11-27T03:00:00Z);   // drill: pause flag set at 14:00 AEDT
MicrosoftGraphActivityLogs
| where TimeGenerated >= dayStart and TimeGenerated < dayEnd
| where AppId == agentAppId
| extend Path = tostring(parse_url(RequestUri).Path)
| extend Allowlisted = case(
      RequestMethod == "GET"   and Path matches regex @"^/v1\.0/users/[^/]+$", true,
      RequestMethod == "POST"  and Path matches regex @"^/v1\.0/users/[^/]+/revokeSignInSessions$", true,
      RequestMethod == "PATCH" and Path matches regex @"^/v1\.0/users/[^/]+$", true,
      false)
| extend UnexpectedIP   = not(ipv4_is_in_any_range(IPAddress, orchestratorEgress)),
         NotCertAuth    = ClientAuthMethod != 2,
         NotAllowlisted = not(Allowlisted),
         AfterKill      = TimeGenerated >= killTime and ResponseStatusCode between (200 .. 299)
| where UnexpectedIP or NotCertAuth or NotAllowlisted or AfterKill
| extend TokenAgeMin = bin((TimeGenerated - TokenIssuedAt) / 1m, 1)
| project TimeGenerated, IPAddress, ClientAuthMethod, RequestMethod, Path, ResponseStatusCode,
          UnexpectedIP, NotCertAuth, NotAllowlisted, AfterKill, TokenAgeMin
| order by TimeGenerated asc
```

`parse_url()` splits the URI so the allowlist matches on the path
without the `$select` query string.

I ran the same logic in Python over the sample rows:

```
total 10 in window 9
ok 2026-11-26T21:58:03Z GET /v1.0/users/m.lee@northwind-example.com
ok 2026-11-26T21:58:05Z POST /v1.0/users/m.lee@northwind-example.com/revokeSignInSessions
2026-11-26T22:15:44Z GET /v1.0/servicePrincipals 200 UnexpectedIP True NotCert True NotAllowlisted True AfterKill False TokenAgeMin 0
2026-11-26T22:16:02Z POST /v1.0/servicePrincipals/9d8c7b6a-5e4f-4a3b-9c2d-1e0f9a8b7c6d/addPassword 403 UnexpectedIP True NotCert True NotAllowlisted True AfterKill False TokenAgeMin 0
2026-11-26T22:16:30Z GET /v1.0/users/m.lee@northwind-example.com 200 UnexpectedIP True NotCert True NotAllowlisted False AfterKill False TokenAgeMin 0
ok 2026-11-27T02:41:20Z GET /v1.0/users/j.patel@northwind-example.com
ok 2026-11-27T02:59:47Z GET /v1.0/users/r.singh@northwind-example.com
2026-11-27T03:01:12Z PATCH /v1.0/users/r.singh@northwind-example.com 204 UnexpectedIP False NotCert False NotAllowlisted False AfterKill True TokenAgeMin 19
2026-11-27T03:01:30Z GET /v1.0/users/r.singh@northwind-example.com 200 UnexpectedIP False NotCert False NotAllowlisted False AfterKill True TokenAgeMin 20
flagged 5
```

**5 flagged requests**: the 3 from `203.0.113.77` (wrong IP and a
secret; the first two also aren't allowlisted) and the 2 that succeeded
after the kill switch, with a token 19 and 20 minutes old. The 4 normal
requests are excluded, and the 23:45 AEDT Thursday row falls outside the
window. The 403 `addPassword` is flagged even though it failed, which is
deliberate: a failed attempt to add credentials is still the most
important row in the table.

**What I verified and what I didn't.** The table columns and the
`ClientAuthMethod` values come from the Azure Monitor table reference,
the API paths from the Graph reference pages, and the token and CAE
behaviour from the Microsoft Learn pages linked above. The agent, its
IDs, the drill and the log rows are fictional. I haven't run the query
against a live workspace.

**Tuning note:**

- **This is a review rule, not a live check.** Microsoft says Graph
  activity log events usually arrive "within 30 minutes" and in less
  common cases "up to 2 hours"
  ([Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)).
  To confirm a kill switch worked *during* an incident, watch the
  agent's own action log. Use this query afterwards to prove nothing got
  past it.
- **Don't hard-code the kill time in production.** Pull it from the
  `AuditLogs` entry for the service principal change, or from the
  orchestrator's own record of the pause, so every pull is checked, not
  just the drill.
- **The allowlist will drift.** Every new tool the agent gets needs a
  line here, or you'll drown in `NotAllowlisted` noise and start
  ignoring it. Treat a change to the agent's permissions and a change to
  this list as one change request.
- **IP allowlists are fragile.** A new egress address after a network
  change will flag everything. Conversely, a Conditional Access location
  policy for the service principal would have *blocked* the requests
  from `203.0.113.77` rather than just reporting them, if Northwind has
  the Workload Identities Premium licences it needs.
- **Graph only.** Device isolation and other Defender actions don't
  appear in this table. They need their own log, which is what Day 25's
  `NWSocAgentActions_CL` is for.
- **Licensing.** Graph activity logs need a Microsoft Entra ID P1 or P2
  tenant licence, per the same Microsoft page.

**References:**
[ATT&CK T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
for the `addPassword` attempt, and
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/)
for the agent-side risks.

---

## Your turn

1. Write Northwind's kill switch runbook in five lines or fewer: which
   layers to pull, in what order, who's allowed to pull each one, how
   you confirm each one worked, and who signs off on turning the agent
   back on.
2. The `PATCH` at 03:01:12 disabled `r.singh` after the drill had
   started. Write the rollback entry: what state should have been
   recorded first, who decides whether to re-enable the account, and
   what you do if the detection behind that task turns out to be right.
3. The three requests from `203.0.113.77` used a forgotten client
   secret. List your first five response steps in order, and say which
   control would have stopped the `m.lee` read that succeeded.
4. Should Northwind's agent declare `cp1` and use CAE? Argue both sides
   in a paragraph each, then make a call.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- CISA, ASD's ACSC and partners: [Careful adoption of agentic AI services](https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services) ([PDF](https://media.defense.gov/2026/Apr/30/2003922823/-1/-1/0/CAREFULADOPTIONOFAGENTICAISERVICES_FINAL.PDF))
- Microsoft Learn: [What is Microsoft Entra Agent ID?](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id) · [Agent identities](https://learn.microsoft.com/en-us/entra/agent-id/agent-identities)
- Microsoft Learn: [Continuous access evaluation for workload identities](https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation-workload) · [Access tokens in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens)
- Microsoft Learn: [MicrosoftGraphActivityLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs) · [Access Microsoft Graph activity logs](https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview)
- Microsoft Graph: [user: revokeSignInSessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0) · [servicePrincipal: addPassword](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword?view=graph-rest-1.0)
- OWASP: [Top 10 for Agentic Applications 2026](https://genai.owasp.org/top-10-for-agentic-applications-2026/)
- MITRE ATT&CK: [T1098.001 Additional Cloud Credentials](https://attack.mitre.org/techniques/T1098/001/)
- This log: [ANALYSIS.md, The line on autonomous containment](../ANALYSIS.md#the-line-on-autonomous-containment) · [Day 17](2026-11-19-agent-tools-mcp-permissions-tool-poisoning.md) (agent tools and permissions) · [Day 19](2026-11-21-logging-llm-apps-detect-abuse.md) (logging LLM apps) · [Day 25](2026-11-27-autonomous-containment-reversibility-blast-radius.md) (reversibility and blast radius)

⬅️ [Learning log index](README.md) · ➡️ Day 27: Mini case: putting it all together (29 Nov)
