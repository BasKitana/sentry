# Your Own AI I.T.

A local AI system-health assistant for Windows. Describe a problem in plain language — it investigates your PC, tells you what it found, and either fixes it automatically (for safe, reversible things) or asks for your explicit yes/no before doing anything that actually changes your system.

```
Running startup health check...

-> Get cpu usage...
-> Get memory usage...
-> Get disk usage...

| Metric | Reading      | Status |
|--------|--------------|--------|
| CPU    | 6% total     | Good   |
| RAM    | 8.8/15.7 GB  | Good   |
| Disk   | 300 GB free  | Good   |

Nothing needs fixing.
```

## How it decides what to do

Every action falls into one of three tiers, enforced in code (not left to the AI's judgment):

- **AUTO** — runs immediately: read-only checks, clearing temp files, flushing DNS, restarting a stuck process, toggling a startup app.
- **APPROVAL** — asks you first, and creates a rollback point (a Windows System Restore point, or a file backup) before doing anything: deleting a file, killing an unrecognized process, changing your power plan, optimizing a drive.
- **BLOCKED** — refuses outright, always: editing the registry directly, touching boot configuration, disabling security software. No override exists for these — they're not implemented in the code at all, so there's nothing to bypass.

The AI never gets raw command-line or shell access. It can only call a fixed set of named, reviewed functions — it can't do anything the code doesn't explicitly allow.

## Setup

**Requirements**: Windows 10/11, Python 3.10+, a free [DeepSeek API key](https://platform.deepseek.com/).

```powershell
git clone https://github.com/BasKitana/your-own-ai-it.git
cd your-own-ai-it

py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

copy .env.example .env
# open .env and paste in your DeepSeek API key
```

## Running it

```powershell
python main.py
```

It runs a health check automatically on startup, then you can keep asking follow-up questions until you press Enter with nothing typed. For System Restore points to work (needed before approval-tier actions), run your terminal as Administrator — read-only checks and file backups work fine either way.

## Running the tests

```powershell
pip install -r requirements-dev.txt
python -m pytest tests\ -v
```

160 tests, fully mocked — no API calls, no changes to your real system.

## Status

This is an early-stage personal project, not a finished product. The safety architecture (the tier system above) has been through multiple adversarial review passes and has real test coverage, but the AI's live behavior against the real DeepSeek API is still only partially verified — see `CLAUDE.md` for the specific known gaps if you're going to work on the code. Use it, but don't assume it's flawless: it's asking for your approval before anything risky specifically *because* neither the AI nor the code is guaranteed perfect.

## License

Not yet chosen — for now, treat this as source-available for personal use, not licensed for redistribution.
