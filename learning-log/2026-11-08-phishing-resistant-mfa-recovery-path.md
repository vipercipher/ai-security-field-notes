# Day 06 — Phishing-Resistant MFA and the Recovery Path

📅 8 November 2026 · 🏷️Deepfake fraud · ⏱️ ~25 min

---

## Why it matters

Day 05 ended with a help desk that can be talked into resetting someone's MFA.
Today is the other half of that problem: what are you resetting *to*, and what
else is still sitting in the account that works just as well for an attacker?

ANALYSIS.md makes the point that phishing-resistant MFA is the best single
investment against the help desk and adversary-in-the-middle route, and also
that it only works if the recovery path is equally strong. Both halves matter.
A FIDO2 key that can't be phished is wasted if the same account also accepts a
text message, a push approval, or a Temporary Access Pass handed out on one
phone call. The attacker uses the weakest door, and the account's strength is
the weakest method that still signs in.

---

## The concept

### What "phishing-resistant" means

NIST SP 800-63B-4 defines it as the ability of the authentication protocol to
prevent disclosure of authentication secrets and valid authenticator outputs to
an impostor verifier **without relying on the vigilance of the claimant**. The
last part is the useful bit: it isn't "the user is trained to spot fake pages".
The protocol itself refuses to work on the wrong site.

NIST also says authenticators that involve **manual entry** of an output (SMS
codes, app one-time codes) can't be phishing-resistant, because typing a code
doesn't bind it to the session it is for. It recognises two ways to get there:
channel binding and verifier name binding. WebAuthn/FIDO2 is NIST's example of
the second: the credential is tied to the real site's name, so a look-alike
domain gets nothing usable.

### What Microsoft Entra counts

Microsoft's Conditional Access authentication strengths page lists three
built-ins. As read on 8 November 2026 (the page is updated when new methods
arrive, so check it again):

| Method | MFA strength | Passwordless MFA | Phishing-resistant MFA |
|---|---|---|---|
| FIDO2 security key | Yes | Yes | **Yes** |
| Windows Hello for Business / platform credential | Yes | Yes | **Yes** |
| Certificate-based authentication (multifactor) | Yes | Yes | **Yes** |
| Microsoft Authenticator (phone sign-in) | Yes | Yes | No |
| Temporary Access Pass | Yes | No | **No** |
| Password plus text, voice, push or OATH code | Yes | No | No |

The row to stare at is the **Temporary Access Pass**: it satisfies ordinary
MFA, but not the phishing-resistant strength. Authenticator phone sign-in is
passwordless and still not in the strongest group. Microsoft's page doesn't give
the reason; my reading (judgement, not Microsoft's wording) is that it still
relies on the user approving a prompt.

### The recovery path is where strength leaks

An account's real strength is the best method an attacker can *reach*, not the
best method the user *has*. Here are the usual leaks:

| Leak | How it undercuts strong MFA | Fix to consider | Trade-off |
|---|---|---|---|
| **Old methods left registered** | SMS or Authenticator push remain valid next to the new key. Microsoft's own TAP guidance says users who replace methods after a loss should remove the old ones | Remove weak methods when the strong one is enrolled; scope the Authentication methods policy | Users who lose their only key now have nothing; you need a tested recovery plan |
| **Strength only on some apps** | A policy that demands phishing-resistant sign-in for the admin portal does nothing for an app outside its scope | Apply the strength to the apps and users that matter most first: admins, finance, help desk | Wider scope means more lock-outs |
| **TAP as the recovery bootstrap** | Microsoft documents a TAP as a time-limited passcode, single or multi-use, with lifetime 10 minutes to 30 days (default maximum 8 hours). Whoever gets it can sign in and register a new method | Single use, short lifetime, only issued after a strong check (Day 05) | Short single-use passes can expire mid-setup, which pushes staff to ask for longer ones |
| **Sessions that outlive the pass** | Microsoft says expiry of a TAP doesn't retroactively invalidate sessions already established; tokens are capped at the TAP expiry only at issuance | Set sign-in frequency for sensitive apps | More prompts for everyone |
| **Initial sign-in isn't restricted** | Microsoft notes a strength doesn't restrict the initial authentication. A user can still type a password, and then must satisfy the strength | Not a gap by itself, but know that a password can still be tried | None. Just a fact to keep in mind |

### What NIST says about recovery

NIST SP 800-63B-4 section 4.2 describes four classes of recovery method
(saved recovery codes, issued recovery codes, recovery contacts, repeated
identity proofing). For an account that can authenticate at AAL2 it requires
one of: two recovery codes obtained by different methods, one recovery code
plus a single-factor authenticator already bound to the account, or repeated
identity proofing. It also says an account recovery event **always** causes
notification to the subscriber, with instructions in case they didn't do it.

That last rule maps directly to a gap in many shops: a notification that goes
to the mailbox the attacker is already inside is worth little. Notifications
should go to a second channel the person can reach.

> 💡 **Judgement call:** I'd rather have a smaller set of strong methods and a
> slow, human, well-documented recovery than a broad set of "also works"
> methods. Every fallback you keep is a credential you have to protect as
> well as the strong one. This is my view, not a Microsoft recommendation.

### Where this stops helping

Phishing-resistant MFA protects the sign-in. It does nothing against a
convincing voice that asks a finance officer to pay an invoice from their own
legitimate session (Day 01, Day 04). That is still a process control problem.

---

## Sample logs

All times are UTC on **Friday 6 November 2026** (Sydney is UTC+11). All data is
fictional, and the IPs are documentation ranges. This is a **simplified,
flattened extract inspired by Entra's `SigninLogs` table**: each row is one
successful sign-in, and `Methods` stands in for the successful steps in the
`AuthenticationDetails` column. The real column holds a JSON array, and the
exact method strings should be checked in your own tenant. Northwind's policy
(fictional) says Northwind Payments and Azure Portal should only be reached
with a phishing-resistant method, and it is running in **report-only mode**, so
weak sign-ins still succeed and get logged.

```
Time   User      App                 IP             Methods
00:58  a.chen    Northwind Payments  203.0.113.10   Password, FIDO2 security key
01:10  b.diaz    Northwind Payments  203.0.113.11   Password, Windows Hello for Business
01:15  c.ng      Azure Portal        203.0.113.12   Password, FIDO2 security key
01:40  d.ward    Northwind Payments  198.51.100.7   Password, Mobile app notification
02:05  e.ito     Azure Portal        198.51.100.23  Password, Text message
02:30  f.cole    Northwind Payments  192.0.2.44     Temporary Access Pass
03:02  a.chen    Northwind Payments  203.0.113.10   Password, FIDO2 security key
03:20  g.mehta   Northwind Intranet  203.0.113.20   Password, Mobile app notification
03:45  d.ward    Northwind Payments  198.51.100.7   Password, Mobile app notification
04:10  h.park    Azure Portal        203.0.113.13   Password, FIDO2 security key
04:30  i.sato    Azure Portal        203.0.113.14   Previously satisfied
05:00  j.khan    Northwind Payments  203.0.113.15   Password, Windows Hello for Business
```

What was found out later (fictional): `d.ward` hadn't enrolled a key yet and was
using the old Authenticator push. `e.ito` had a spare text-message method
registered from years ago, and the sign-in came from an unfamiliar IP.
`f.cole` had lost a phone, and Tuesday's help desk call (a Day 05-style reset)
had issued a Temporary Access Pass.

---

## What to look for

1. **Count first.** 12 successful sign-ins. 11 went to the two protected apps,
   and 1 (`g.mehta`, Northwind Intranet) didn't. Of the 11, **6** used a
   phishing-resistant method, 1 was `Previously satisfied`, and **4** did not.
2. **Same user, repeated weak sign-ins.** `d.ward` accounts for 2 of the 4.
   That looks like a rollout gap, not an attack: same IP, same method, same app.
3. **The unfamiliar IP.** `e.ito` signed in with a text message from
   `198.51.100.23`, which no other user in the extract shares. A weak method
   and an odd source together is worth a look. A weak method on its own is a
   coverage issue.
4. **A TAP sign-in to a protected app.** `f.cole` used only a Temporary Access
   Pass. In a recovery that is expected. Using it on Northwind Payments rather
   than just on the security info page is not, and it suggests the strength
   policy isn't enforced yet. What `f.cole` does next (registers a new method?
   adds a mail rule?) is Day 07.
5. **`Previously satisfied`.** `i.sato` has no new method because an earlier
   sign-in's MFA was reused. That row tells you nothing about strength, so the
   rule below skips it. It's a blind spot: you'd have to trace the earlier
   sign-in in that session to judge it.
6. **Out of scope on purpose.** `g.mehta` used a push to the intranet. That is
   allowed under Northwind's fictional policy. A rule that flags it would
   train people to ignore it.

---

## Detection logic

**In plain English:** find successful sign-ins to the protected apps where none
of the successful authentication steps is a phishing-resistant method. Skip
sign-ins that were satisfied by an earlier session, and group by user.

**KQL (Microsoft Sentinel / Log Analytics, `SigninLogs`):**

```kql
// Protected app reached without a phishing-resistant method
let protectedApps = dynamic(["Northwind Payments", "Azure Portal"]);
let strongMethods = dynamic(["FIDO2 security key",
                             "Windows Hello for Business",
                             "X.509 Certificate"]);   // check the strings in your tenant
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| where ResourceDisplayName in (protectedApps)
| mv-expand step = parse_json(AuthenticationDetails)
| where tobool(step.succeeded)
| summarize Methods = make_set(tostring(step.authenticationMethod)),
            Time = min(TimeGenerated)
    by CorrelationId, UserPrincipalName, ResourceDisplayName, IPAddress
| where array_length(set_intersect(Methods, strongMethods)) == 0
| where not(set_has_element(Methods, "Previously satisfied"))
| summarize WeakSignIns = count(), Apps = make_set(ResourceDisplayName),
            IPs = make_set(IPAddress), Methods = make_set(Methods)
    by UserPrincipalName
```

The column names (`ResultType`, `ResourceDisplayName`, `AuthenticationDetails`,
`CorrelationId`, `UserPrincipalName`, `IPAddress`) come from Microsoft's
`SigninLogs` reference. `ResultType` is documented as `0` for success. The
method strings inside `AuthenticationDetails` are **not** something I verified
for every method, so print them from your own logs before trusting the filter.

I ran the same logic over the sample rows in Python. It returns **3 users and 4
sign-ins**:

```
User     WeakSignIns  Methods
d.ward   2            Password + Mobile app notification
e.ito    1            Password + Text message
f.cole   1            Temporary Access Pass
```

And it drops the other eight rows: 6 used a strong method (a.chen twice,
b.diaz, c.ng, h.park, j.khan), 1 was `Previously satisfied` (i.sato), and 1 was
not a protected app (g.mehta).

**Tuning note:** while Conditional Access is in report-only mode this is a
rollout tracker: every hit is someone who would be locked out the day you
enforce. Work down it by user and fix enrolment first. Once enforcement is on,
weak sign-ins to protected apps should be impossible, so any hit means a
policy exclusion or a gap in scope. That is a much more serious finding, and
you should treat it as one. Break-glass accounts will appear by design. Exclude
them from this rule but alert separately on *any* sign-in by them. Don't
suppress `TemporaryAccessPass` hits just because recovery is a good reason:
a TAP on a protected app is the one you want a person to look at. The rule
also misses single-factor and token-replay cases, so it is a coverage check and
not a complete detection.

---

## Your turn

1. In your own words, why does a text message code not count as
   phishing-resistant even though it is a second factor? Use "manual entry" and
   "impostor" in your answer.
2. `d.ward` and `e.ito` both signed in weakly. Write what you would check next
   for each, and say which one you would escalate first and why.
3. Northwind enforces phishing-resistant MFA for finance and admins. An admin
   loses their only security key while travelling. Write the recovery steps
   from the admin's call to a working sign-in. Which step is slowest, and what
   weaker method are you tempted to allow to speed it up?
4. Pick one old method (SMS, Authenticator push or a spare phone number) and
   argue for or against removing it from every protected user this month. Name
   one person who gets hurt by your choice.

---

## My answers

<!-- Answer each question in your own words, then commit. -->

1.

2.

3.

4.

---

## Further reading

- Microsoft Learn: [Conditional Access authentication strengths](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-strengths)
- Microsoft Learn: [Configure a Temporary Access Pass](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass)
- Microsoft Learn: [SigninLogs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs)
- NIST: [SP 800-63B-4, Authenticators (phishing resistance)](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/)
- NIST: [SP 800-63B-4, Authenticator event management (account recovery and notification)](https://pages.nist.gov/800-63-4/sp800-63b/events/)
- This log: [ANALYSIS.md](../ANALYSIS.md) (identity controls) · [Day 05](2026-11-07-help-desk-social-engineering.md) (verifying the caller before issuing a TAP)

⬅️ [Learning log index](README.md) · ➡️ Day 07: After the reset: detecting MFA changes and inbox rules (9 Nov)
