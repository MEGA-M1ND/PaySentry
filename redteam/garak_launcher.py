"""Launcher that runs INSIDE .venv-garak, patching one upstream bug first.

Do not run this with the project's main interpreter -- it imports garak, which
only exists in the quarantined venv. Use redteam/run_garak.py instead.

THE BUG (garak 0.9.0.11.post1, garak/generators/rest.py)
--------------------------------------------------------
RestGenerator hardcodes a 10 second HTTP timeout:

    line 109:  self.request_timeout = 10          # default, never overridden
    line 124:  "response_timeout",                # the field read from config
    line 232:  timeout=self.request_timeout,      # what the request uses

The config field garak documents and reads is `response_timeout`, but the
request uses `request_timeout`. Setting either in garak_config.json is
therefore inert: `response_timeout` lands on an unused attribute, and
`request_timeout` isn't in the accepted field list at all.

Why that matters here: a single turn against gpt-5.2 takes ~4-15s because the
agent runs a full ReAct loop (model -> tool -> model). With a 10s ceiling most
probes fail as timeouts, which would look like a hardened target rather than a
broken harness -- a false SECURE, the worst possible failure mode for a
security tool.

So we patch the attribute after construction and hand off to garak's real CLI.
Override the value with GARAK_REQUEST_TIMEOUT if needed.
"""

import os
import sys

from garak.generators.rest import RestGenerator

_TIMEOUT = int(os.getenv("GARAK_REQUEST_TIMEOUT", "180"))
_original_init = RestGenerator.__init__


def _patched_init(self, *args, **kwargs):
    _original_init(self, *args, **kwargs)
    self.request_timeout = _TIMEOUT


RestGenerator.__init__ = _patched_init

if __name__ == "__main__":
    print(f"[paysentry] RestGenerator.request_timeout patched to {_TIMEOUT}s")
    from garak import cli

    cli.main(sys.argv[1:])
