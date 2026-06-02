from __future__ import annotations

PLUGIN_NAME = "PseudoForge"
VERSION = "0.1.1"
__version__ = VERSION


def plugin_title() -> str:
    return "%s %s" % (PLUGIN_NAME, VERSION)
