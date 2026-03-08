# 🔐 Password Strength Analyzer & Breach Checker

A command-line tool that analyzes password strength and checks if a password has appeared in known data breaches — built with Python.

---

## Features:

- Scores passwords from 0 to 100 with a visual strength bar
- Checks length, character variety, entropy, repeated characters, and common patterns
- Detects passwords from the most commonly guessed list
- Queries the **HaveIBeenPwned API** using the **k-anonymity model** — your password is never sent over the network
- Supports single password analysis and batch mode (list of passwords from a file)
- Color-coded terminal output

---

## How the Breach Check Works:

Only the first 5 characters of your password's SHA-1 hash are sent to the API.
The full hash is matched locally — your actual password never leaves your machine.

```
Password  →  SHA-1 Hash  →  First 5 chars sent to API
                             API returns ~800 matching hashes
                             Full hash matched locally  ✔
```
---
## Example Output:

```
  ┌────────────────────────────────────────────────────────────┐
  │  PASSWORD STRENGTH REPORT                                  │
  │  By Takalani Netshilaphala - Aspiring Cyber Analyst        │
  ├────────────────────────────────────────────────────────────┤
  │                                                            │
  │  Password      ••••••••••••                                │
  │  Strength      Very Strong                                 │
  │  Score         ████████████████████  95/100                │
  │  Length        18 characters                               │
  │  Entropy       107.4 bits                                  │
  │  HIBP          Clean — not found in any breach database    │
  │                                                            │
  ├────────────────────────────────────────────────────────────┤
  │                                                            │
  │  CRITERIA MET                                              │
  │                                                            │
  │    ✔  18 characters (excellent — 16+)                      │
  │    ✔  Contains uppercase letters (A–Z)                     │
  │    ✔  Contains lowercase letters (a–z)                     │
  │    ✔  Contains numbers (0–9)                               │
  │    ✔  Contains special characters (!@#$...)                │
  │    ✔  Not in the common passwords list                     │
  │                                                            │
  └────────────────────────────────────────────────────────────┘
```
---

## Tech Stack:

| | |
|---|---|
| Language | Python 3.11+ |
| HTTP Client | httpx |
| Terminal Colors | colorama |
| Testing | pytest |

---

## Disclaimer:

Built for educational purposes only. Use responsibly on passwords you own.

---

## Author:

**Takalani Netshilaphala** — CS & IT Student 
🔗 [LinkedIn](https://www.linkedin.com/in/takalani-netshilaphala-74814b282)
