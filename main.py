"""S.E.N.T.R.Y. entry point.

Loads configuration, does a best-effort elevation check, takes the user's
problem description, and hands it to the DeepSeek tool-calling agent loop.
"""
import ctypes
import os
import sys

from dotenv import load_dotenv
from openai import OpenAI

import config
import diagnostics, actions, blocked  # noqa: F401  (registration side effect only)
import agent


def _check_admin() -> None:
    """Warn (do not hard-block) if not running elevated. Creating a System
    Restore point needs elevation; read-only diagnostics and file-backup
    actions don't."""
    try:
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        is_admin = False

    if not is_admin:
        print(
            "[warning] Not running as Administrator. Read-only diagnostics and file-backup "
            "actions will still work, but creating a System Restore point (used as the "
            "rollback safety net before APPROVAL-tier actions) requires elevation. Consider "
            "re-running this from an elevated terminal.\n"
        )


def _build_client() -> OpenAI:
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        print(
            "Missing DEEPSEEK_API_KEY. Copy .env.example to .env, fill in your DeepSeek API "
            "key, and run this again."
        )
        sys.exit(1)
    return OpenAI(api_key=api_key, base_url=config.DEEPSEEK_BASE_URL)


_STARTUP_SCAN_PROMPT = (
    "Do a full startup health check: CPU, memory, disk space, the heaviest running "
    "processes, startup items, and temp file buildup. Report anything worth the user's "
    "attention. If you find exactly one clear, safe issue to fix, propose the fix as usual; "
    "if there's nothing worth fixing, say so plainly instead of forcing an action."
)


def main() -> None:
    load_dotenv()
    _check_admin()
    client = _build_client()

    # One growing history for the whole session, so a follow-up like "what
    # would disabling it do" can resolve "it" against something the startup
    # scan (or an earlier follow-up) already found — short-term memory only,
    # never written to disk, gone when this process exits.
    history = agent.new_history()

    print("Running startup health check...\n")
    print(agent.run(client, _STARTUP_SCAN_PROMPT, history=history))

    while True:
        print()
        problem = input("Anything else? (Enter to exit) ").strip()
        if not problem:
            return
        print()
        print(agent.run(client, problem, history=history))


if __name__ == "__main__":
    main()
