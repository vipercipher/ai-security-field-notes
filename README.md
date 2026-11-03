# 🤖 AI Security Field Notes

**A daily log on what AI has actually changed in cybersecurity: deepfake fraud,
LLM security and AI in the SOC.**

Written during November 2026 as the follow-up to my
[Beginner SOC Lab](https://github.com/vipercipher/soc-lab-beginner) and its
October learning log.

## Start here

- 📄 **[The full analysis](ANALYSIS.md):** the three areas in one long read, with
  the controls that work, where tools still fail and a 90-day priority list.
- 📓 **[The 28-day learning log](learning-log/README.md):** one topic a day, each
  with fictional sample logs, a detection rule and exercises.

## The three areas

| Part | Question | Days |
|---|---|---|
| **Deepfakes and social engineering** | How is the fraud really done, and what stops it? | 01–09 |
| **LLM security** | How do you run an LLM or agent when injection can't be fully solved? | 10–19 |
| **AI in the SOC** | Where does AI help analysts, and how far should autonomy go? | 20–26 |
| **Wrap-up** | Mini case and month recap | 27–28 |

## Ground rules

- **Defensive only.** No working malware, exploit code or real phishing content.
- **Fictional data.** Northwind is a made-up company. IP addresses use
  documentation ranges (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`) and domains
  use `*.example` or `northwind-example.com`.
- **Sources first.** Claims about real incidents link to published reports.
  Thresholds in rules and recommendations are starting points to tune.
- **Made with AI help, and open about it.** Lessons and the analysis are drafted
  with Claude, an AI assistant. The "My answers" sections are my own work.

## Licence

[MIT](LICENSE)
