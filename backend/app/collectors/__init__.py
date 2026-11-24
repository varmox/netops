"""Config collectors. Each returns a list of (filename_suffix, bytes, comparable_text_or_None)."""
from . import mikrotik, zyxel

COLLECTORS = {
    "mikrotik-ssh": mikrotik.collect,
    "zyxel-zcfg": zyxel.collect,
}
