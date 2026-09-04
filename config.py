"""Your Own AI IT — configuration constants.

Model constants and loop tuning for the DeepSeek-V4-Flash agent loop.
BACKUP_ROOT (rollback file-backup location) lives in rollback.py, not here.
"""

DEFAULT_MODEL = "deepseek-v4-flash"
ESCALATION_MODEL = "deepseek-v4-pro"  # config hook only, not wired up yet
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
MAX_TOKENS = 8192  # bumped from 4096: the one observed empty-response failure involved 6 tool
                    # calls including two full process listings — plausible the model was
                    # still processing that volume when it hit the token ceiling. Unconfirmed
                    # (see CLAUDE.md "Known state"), but cheap and safe to hedge against.
MAX_ITERATIONS = 8
