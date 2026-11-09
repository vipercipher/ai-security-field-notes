# 📓 AI Security Learning Log — November 2026

A 28-day, one-topic-a-day log on how AI is changing security work: **deepfake
fraud, LLM security and AI in the SOC**. It follows on from the
[October SOC log](https://github.com/vipercipher/soc-lab-beginner/blob/main/learning-log/README.md),
and each entry ends with exercises answered in my own words.

> **How this log is made:** each day's lesson (concept, sample logs, detection
> logic) is drafted with help from Claude, an AI assistant, following the plan
> below. The **"My answers"** section at the bottom of every entry is mine,
> written after working through the exercises. All sample data is fictional, and
> IP addresses use the ranges reserved for documentation (`192.0.2.x`,
> `198.51.100.x`, `203.0.113.x`).

---

## How each entry is laid out

| Section | What it covers |
|---|---|
| **Why it matters** | Where this shows up in real security work |
| **The concept** | The idea, explained from the ground up |
| **Sample logs** | A small fictional log extract to read |
| **What to look for** | The patterns an analyst spots |
| **Detection logic** | How to turn the pattern into a rule (Sigma, KQL or SPL) |
| **Your turn** | 3–4 exercises |
| **My answers** | My own write-up of the exercises |
| **Further reading** | Official docs and references |

---

## 🗓️ The plan

### Part 1: Deepfakes and social engineering

| Day | Date | Topic | Entry |
|---|---|---|---|
| 01 | 3 Nov | Deepfake BEC: anatomy of the attack | [Read](2026-11-03-deepfake-bec-anatomy.md) |
| 02 | 4 Nov | Voice cloning: what it takes and where it breaks | [Read](2026-11-04-voice-cloning-limits.md) |
| 03 | 5 Nov | Why people and deepfake detectors both miss fakes | [Read](2026-11-05-why-people-and-detectors-miss-fakes.md) |
| 04 | 6 Nov | Payment controls that stop BEC: call-backs and dual approval | [Read](2026-11-06-payment-controls-callbacks-dual-approval.md) |
| 05 | 7 Nov | Help desk social engineering and verifying a caller | [Read](2026-11-07-help-desk-social-engineering.md) |
| 06 | 8 Nov | Phishing-resistant MFA and the recovery path | [Read](2026-11-08-phishing-resistant-mfa-recovery-path.md) |
| 07 | 9 Nov | After the reset: detecting MFA changes and inbox rules | [Read](2026-11-09-mfa-changes-and-inbox-rules.md) |
| 08 | 10 Nov | Vishing over Teams: external tenants and remote access tools | [Read](2026-11-10-teams-vishing-external-tenants-remote-access.md) |
| 09 | 11 Nov | Deepfake job candidates and remote worker fraud | |

### Part 2: LLM security

| Day | Date | Topic | Entry |
|---|---|---|---|
| 10 | 12 Nov | How LLM apps fail: the OWASP LLM Top 10 | |
| 11 | 13 Nov | Direct prompt injection vs jailbreaking | |
| 12 | 14 Nov | Indirect prompt injection: an EchoLeak walkthrough | |
| 13 | 15 Nov | Threat modelling agents: lethal trifecta and Rule of Two | |
| 14 | 16 Nov | Input handling: what sanitisation can and can't do | |
| 15 | 17 Nov | Runtime guardrails and how adaptive attacks beat them | |
| 16 | 18 Nov | Output validation and data exfiltration channels | |
| 17 | 19 Nov | Agent tools and MCP: permissions and tool poisoning | |
| 18 | 20 Nov | Data poisoning: training data, RAG and agent memory | |
| 19 | 21 Nov | Logging LLM apps so you can detect abuse | |

### Part 3: AI in the SOC

| Day | Date | Topic | Entry |
|---|---|---|---|
| 20 | 22 Nov | ML threat hunting: anomalies, UEBA and baselines | |
| 21 | 23 Nov | AI-powered IDS: base rates, precision and drift | |
| 22 | 24 Nov | Incident response copilots: measuring real value | |
| 23 | 25 Nov | Hallucination in playbooks: verifying AI output | |
| 24 | 26 Nov | Prompt injection through logs: attacking the SOC's AI | |
| 25 | 27 Nov | Autonomous containment: reversibility and blast radius | |
| 26 | 28 Nov | Guardrails for SOC agents: identity, rollback and kill switches | |

### Wrap-up

| Day | Date | Topic | Entry |
|---|---|---|---|
| 27 | 29 Nov | Mini case: putting it all together | |
| 28 | 30 Nov | Month recap and what to study next | |

---

## Progress

- Entries published: **8 / 28**
- Exercises answered: tracked in each entry's **My answers** section

➡️ Back to the [main page](../README.md) · 📄 Read the [full analysis](../ANALYSIS.md).
