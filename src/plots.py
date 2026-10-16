"""Shared matplotlib styling for report figures."""
import config

ATTACK_ORDER = ["brute_force", "low_and_slow", "password_spraying", "credential_stuffing",
                "user_enumeration", "post_compromise"]


def type_color(attack_type):
    """benign = slot 1, attack types = slots 2-7 in fixed order, anything else muted."""
    if attack_type == "benign":
        return config.COLORS[0]
    if attack_type in ATTACK_ORDER:
        return config.COLORS[ATTACK_ORDER.index(attack_type) + 1]
    return config.MUTED


def style(ax, title, xlabel=None, ylabel=None):
    ax.set_title(title, loc="left", fontsize=12, color=config.INK, pad=10)
    if xlabel:
        ax.set_xlabel(xlabel, color=config.MUTED)
    if ylabel:
        ax.set_ylabel(ylabel, color=config.MUTED)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color("#c3c2b7")
    ax.tick_params(colors=config.MUTED)
    ax.grid(axis="y", color=config.GRID, linewidth=0.6)
    ax.set_axisbelow(True)
