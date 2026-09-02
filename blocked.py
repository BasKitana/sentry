"""S.E.N.T.R.Y. BLOCKED-tier tool registrations.

These are the actions the model may never take, now or with any future
override. Each entry here is schema + description ONLY — there is no
function to call. This is deliberate, structural defense in depth:
safety.register_blocked() never accepts a `func` argument and always
stores None, so even if the tier check in safety.dispatch() were ever
weakened or bypassed by a bug elsewhere, there would still be nothing
behind these names that could touch the OS. The refusal is enforced by
absence, not by a policy flag that could be flipped.

Import this module (for its registration side effects) alongside
diagnostics and actions before building the tool list — see main.py.
"""

import safety

safety.register_blocked(
    name="edit_registry",
    description=(
        "Write, create, or delete a Windows Registry key or value directly (e.g. under "
        "HKEY_LOCAL_MACHINE or HKEY_CURRENT_USER). Refused because a single bad "
        "registry edit can silently corrupt Windows configuration in ways that are "
        "hard to diagnose and can require a full reinstall to fix, and because a "
        "general-purpose registry writer is too broad a capability to safely bound. "
        "Narrow, specific registry changes that ARE safe (like toggling a startup "
        "item on or off) are exposed instead through their own validated tool, not "
        "through raw registry access."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "hive": {
                "type": "string",
                "description": "Registry hive, e.g. 'HKEY_LOCAL_MACHINE' or 'HKEY_CURRENT_USER'.",
            },
            "key_path": {
                "type": "string",
                "description": "Path of the registry key to modify.",
            },
            "value_name": {
                "type": "string",
                "description": "Name of the value to set, if applicable.",
            },
            "value_data": {
                "type": "string",
                "description": "Data to write to the value, if applicable.",
            },
        },
        "required": ["hive", "key_path"],
    },
)

safety.register_blocked(
    name="modify_boot_configuration",
    description=(
        "Change Windows boot configuration data (BCD) — boot order, boot manager "
        "entries, startup/recovery options, or any bcdedit-equivalent setting. "
        "Refused because a mistake here can leave the machine unable to boot at all, "
        "with no way to recover from inside a running OS session; this class of "
        "irreversible, catastrophic risk is excluded entirely rather than merely "
        "gated behind an approval prompt."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "setting": {
                "type": "string",
                "description": "The boot configuration setting to change (e.g. 'bootorder', 'timeout', 'default').",
            },
            "value": {
                "type": "string",
                "description": "The desired new value for the setting.",
            },
        },
        "required": ["setting"],
    },
)

safety.register_blocked(
    name="disable_security_software",
    description=(
        "Disable, uninstall, or otherwise weaken antivirus, firewall, Windows "
        "Defender, or any other protective/security software running on the machine. "
        "Refused because turning off the system's defenses is exactly what a "
        "compromised session or a malicious actor impersonating a legitimate "
        "troubleshooting request would want, and no genuine 'my PC is slow / acting "
        "up' scenario requires it. If security software is itself the source of a "
        "problem, that calls for deliberate, informed action by the user directly, "
        "not an automated tool."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "product_name": {
                "type": "string",
                "description": "Name of the security product to disable, if known.",
            },
        },
        "required": [],
    },
)

safety.register_blocked(
    name="permanently_delete_bypassing_recycle_bin",
    description=(
        "Permanently delete a file or folder by a route that skips the Recycle Bin "
        "entirely (e.g. a Shift+Delete-equivalent or a direct filesystem unlink), so "
        "there is no recoverable trash to restore from. Refused because it removes "
        "the one safety net that makes an accidental or mistaken deletion "
        "recoverable. Permanent deletion is still available through "
        "'permanently_delete_file', which is APPROVAL-tier, backs the file up before "
        "acting, and reports where the backup went — this tool exists specifically to "
        "deny the version that has no such net."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path of the file or folder to delete without using the Recycle Bin.",
            },
        },
        "required": ["path"],
    },
)

safety.register_blocked(
    name="write_to_system_directory",
    description=(
        "Create, modify, replace, or delete a file inside a protected Windows system "
        "directory (e.g. C:\\Windows, C:\\Windows\\System32, or C:\\Program Files\\Windows*). "
        "Refused because these directories hold the files the operating system itself "
        "depends on to run; an unsupervised write here can destabilize or break "
        "Windows outright and is very hard to diagnose after the fact. No routine "
        "'fix a problem on my PC' task legitimately needs direct writes to these "
        "locations."
    ),
    input_schema={
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Target path inside a protected Windows system directory.",
            },
            "content": {
                "type": "string",
                "description": "Content that would have been written, if applicable.",
            },
        },
        "required": ["path"],
    },
)
