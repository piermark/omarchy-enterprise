# Workstation security

Enterprise Guard checks managed configuration against a saved baseline.
Review unexpected drift before updating the baseline. The package provides
an [example Pacman hook](../templates/90-omarchy-enterprise-guard.hook.example).
Review its scope and the tested scope in [availability](availability.md) before opting in.

Keep the Control Center in the regular user session, retain local
administrator access and review the exact proposed changes before granting
approval. Store configuration drafts, receipts, journals and backups
privately. Verify any distributed package against the maintainer's trusted
fingerprint, signature and checksum list.

Inbound remote desktop remains off. Graphical domain login and directory
integration were exercised on the reference workstation; clean-install
acceptance and Windows guest isolation are pending. Use the
[security policy](../SECURITY.md) to report a vulnerability privately.
