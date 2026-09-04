"""Your Own AI IT — CLI presentation layer.

rich-based narration and confirmation prompts. This module has no OS side
effects of its own — it only ever talks to the terminal. `safety.dispatch()`
calls into `confirm_action`/`confirm_without_rollback`; `agent.run()` calls
`narrate` before every tool dispatch.
"""
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

console = Console()


def narrate(tool_name: str, tool_input: dict) -> None:
    """Print a one-line status update right before a tool call is dispatched."""
    label = tool_name.replace("_", " ").capitalize()
    if tool_input:
        args = ", ".join(f"{k}={v!r}" for k, v in tool_input.items())
        console.print(f"[cyan]-> {label}...[/cyan] [dim]({args})[/dim]")
    else:
        console.print(f"[cyan]-> {label}...[/cyan]")


def narrate_debug(message: str) -> None:
    """Print a dim diagnostic line for an unexpected-but-handled situation in
    the agent loop (e.g. an empty final response from the model). Not shown
    for normal operation — only when something worth a human noticing happened."""
    console.print(f"[dim yellow][debug] {message}[/dim yellow]")


def confirm_action(spec: Any, tool_input: dict) -> bool:
    """Ask the user to approve an APPROVAL-tier tool call.

    `spec` is a safety.ToolSpec. It's duck-typed here (not imported) to avoid
    a ui<->safety circular import, since safety.dispatch() calls into ui.
    """
    lines = [f"[bold]{spec.name}[/bold]", "", spec.description]
    if tool_input:
        lines.append("")
        lines.append("Arguments:")
        for key, value in tool_input.items():
            lines.append(f"  [cyan]{key}[/cyan] = {value!r}")
    lines.append("")
    lines.append("[yellow]This will make a real change to your system.[/yellow]")

    console.print(Panel(
        "\n".join(lines),
        title="[bold red]Approval required[/bold red]",
        border_style="red",
    ))
    return Confirm.ask("Proceed?", default=False)


def confirm_without_rollback(detail: str) -> bool:
    """Ask the user to confirm proceeding even though no rollback point or
    file backup could be created. More emphatic than confirm_action — this
    means the action would happen with no safety net."""
    console.print(Panel(
        f"[bold red]No safety net could be created for this action.[/bold red]\n\n"
        f"{detail}\n\n"
        f"If this action goes wrong, there will be nothing to automatically restore from.",
        title="[bold red]Proceed WITHOUT a rollback point?[/bold red]",
        border_style="red",
    ))
    return Confirm.ask("Proceed anyway, with no safety net?", default=False)
