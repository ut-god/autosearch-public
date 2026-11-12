"""Helpers for parsing fully-qualified target identifiers."""
from __future__ import annotations


def split_qualified_target(target: str) -> tuple[str, str] | None:
    """Split `Namespace::Class::method(...)` into class and method parts.

    The split point is the last top-level `::`, ignoring any nested `::`
    that appear inside template arguments or parameter types.
    """
    target = target.strip()
    if "::" not in target:
        return None

    angle_depth = 0
    paren_depth = 0
    bracket_depth = 0
    split_at = -1
    i = 0

    while i < len(target) - 1:
        ch = target[i]
        if ch == "<":
            angle_depth += 1
        elif ch == ">":
            angle_depth = max(0, angle_depth - 1)
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth = max(0, paren_depth - 1)
        elif ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth = max(0, bracket_depth - 1)
        elif (
            ch == ":"
            and target[i + 1] == ":"
            and angle_depth == 0
            and paren_depth == 0
            and bracket_depth == 0
        ):
            split_at = i
            i += 1
        i += 1

    if split_at <= 0:
        return None

    target_class = target[:split_at].strip()
    target_method = target[split_at + 2:].strip()
    if not target_class or not target_method:
        return None
    return target_class, target_method
