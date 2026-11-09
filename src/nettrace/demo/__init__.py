"""Demo lab: a simulated "Acme Corp" hybrid network that nettrace can trace end to end.

`install()` plugs simulators in *below* nettrace's read-only guards (Cisco SSH connection, PAN-OS
XML API session, Strata Cloud Manager HTTP, AWS API), so every real driver, the engine and the
guards run unchanged. Nothing here talks to a network.
"""

from nettrace.demo.lab import PRESETS, install

__all__ = ["PRESETS", "install"]
