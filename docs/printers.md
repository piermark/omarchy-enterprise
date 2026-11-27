# Printers

CUPS manages the local print queues. Use Printers in the Control Center to
inspect local status and draft driverless IPP or IPPS queues. The
[synthetic definitions](../templates/printers.example.json) show the naming
and endpoint format. Use names starting with `oe-` and select at most one
default. An administrator reviews each change against ownership, endpoint
and pending job checks.

Printer discovery and queue inspection were exercised on the reference
workstation. Live queue creation, endpoint updates and undo still need
acceptance; use a disposable CUPS environment and exclusive queue administration. Preserve the receipt after
an interruption and reconcile the queue and jobs before trying again.
See [printing administration](administration.md#printing).
