# Troubleshooting

| Symptom | Review |
| --- | --- |
| Signature or pin rejected | Compare the verified primary fingerprint, signature and archive with the maintainer's independently trusted release details. |
| Bootstrap fails preflight | Check Omarchy version recognition, writable supported mounts and free space. Resolve missing packages from trusted repositories. |
| Native wizard cannot launch | Open a regular desktop session. Confirm PyGObject, GTK4 and Libadwaita prerequisites. |
| Staging folder has pending state | Review recovery or abort for the same private folder using the installer or `provision-image --help`. |
| Approval rejected | Generate a fresh plan from the original handoff. Compare ownership and dependency changes before approval. |
| SMB entry missing | Check trusted policy deployment, native group membership, the ticket and the private bookmark ledger. |
| Printer conflict | Verify the ownership description, endpoint and pending jobs locally. Keep the interrupted receipt for reconciliation. |
| Windows guest unreachable | Keep the disk and container. Review claimed identity, lifecycle state, FreeRDP certificate support and network qualification. |

For domain identity failures, check DNS SSSD uses to discover AD, clock
synchronization, Samba machine trust and SSSD identity resolution before
reviewing PAM or SDDM. Keep a local administrator session available and leave
graphical domain login disabled during source evaluation. See the
[administrator guide](administration.md#active-directory-sssd-and-graphical-login)
and [security policy](../SECURITY.md) before sharing diagnostics.
