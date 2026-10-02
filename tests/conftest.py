# Shared test setup: stub out the `whois` library (not needed for the
# pure helper functions under test) so tests run without it installed.
import sys
import types

whois_mod = types.ModuleType("whois")
whois_mod.whois = lambda domain: None
sys.modules.setdefault("whois", whois_mod)
