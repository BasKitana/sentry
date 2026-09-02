"""S.E.N.T.R.Y. configuration constants.

Model constants and loop tuning for the DeepSeek-V4-Flash agent loop.
BACKUP_ROOT (rollback file-backup location) lives in rollback.py, not here.
"""

DEFAULT_MODEL = "deepseek-v4-flash"
ESCALATION_MODEL = "deepseek-v4-pro"  # config hook only, not wired up yet
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
MAX_TOKENS = 4096
MAX_ITERATIONS = 8
