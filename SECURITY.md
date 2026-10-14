# Security & Regulatory-Accuracy Policy — delivery-guard

## Scope clarification

`delivery-guard` is an **open reference implementation and decision-support tool**.
It is **not a medical device**, **not a certified regulatory submission**, and **not clinical advice**.
Security here means: (a) the integrity of the code, and (b) the accuracy of regulatory references.

## Reporting a vulnerability

1. **Do not open a public Issue.**
2. Email the maintainer via the contact in the repository README, or use GitHub's private security advisory.
3. Include: affected version/commit, reproduction steps, impact, suggested fix.

We aim to acknowledge within **7 days** and provide a remediation plan within **30 days** for confirmed issues.

## Reporting regulatory-accuracy concerns

If a regulatory constant, citation, or date appears wrong or outdated:

1. Open an Issue with label `regulatory-accuracy`.
2. Provide: the exact claim, the official source + version + URL, and the date you verified it.
3. We correct the value and stamp a new "verified on" date. Until then the field stays marked `⚠️ 待核实`.

## Verification tiers (do not overstate)

| Tier | Meaning | What it does NOT mean |
|---|---|---|
| 🟢 CI | GitHub Actions passed | not expert-reviewed, not clinically validated |
| 🟡 Self-test | `--selftest` passes (assertions + negative control) | not third-party audited |
| 🔵 Expert review | a domain expert signed off | currently **pending across the toolkit** |
| ⚪ Official source verification | constant traced to a dated official source | not a guarantee the source is current |

## What we will NOT do

- We will not silently change medical-risk calculations or regulatory judgments for cosmetic reasons.
- We will not present a demo run as a correctness test, nor unaudited code as expert-reviewed.

## Supported versions

Only the latest `main` is supported for security fixes.
