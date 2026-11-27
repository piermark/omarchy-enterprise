# Administrator guide

## Workstation policy

Use the installer or File Servers page to configure the profile and save a
private handoff. Use the installed commands from an authorized administrator
terminal. Review dependencies and ownership before using the short-lived token
that matches the exact input and observed state.

```sh
omarchy-enterprise-admin operational status
omarchy-enterprise-admin operational deploy < deployment.json
omarchy-enterprise-admin operational deploy --approve REVIEW_TOKEN < deployment.json
omarchy-enterprise-admin operational rollback
omarchy-enterprise-admin operational recover
omarchy-enterprise-admin operational abort
```

Review rollback, recover or abort separately and supply its fresh `--approve`
token only after inspecting the current state. Resolve drift before acting.
The policy handoff owns only its operational profile and SMB policy. Keep
existing Guard baselines, hook configuration, user data and legacy resources.

## Active Directory, SSSD and graphical login

Review the generated Samba ADS, SSSD and Kerberos files on the Active
Directory page. Check package and configuration detection with the wizard.
An authorized administrator can use `omarchy-enterprise-admin diagnose`
and `omarchy-enterprise ad-diagnostics` for local checks. In a separately
authorized synthetic domain, review DNS SRV discovery, time synchronization,
Samba machine trust, SSSD configuration, NSS resolution, then PAM and SDDM.
Existing system identity markers require a native trust check and review
before any enrollment. Isolated lab enrollment is described by
`omarchy-enterprise` lab command help. Preserve the enrollment gate and
reconcile ambiguous local and directory state with the directory administrator
before retrying. Enrollment and interactive login were exercised on the reference
workstation; clean-install acceptance is pending (see [availability](availability.md)).

Samba maintains machine trust, SSSD resolves directory users and groups and
integrates with PAM, and Kerberos provides tickets for compatible services.
Use the graphical login review to inspect the SDDM configuration. Keep domain
login disabled during source evaluation and retain a local administrator login
for recovery.

## File servers and Nautilus

Build a policy with friendly names, several shares or servers and optional
qualified AD groups. See [the synthetic policy](../templates/file-servers.example.json).
After administrator deployment, open File Servers to preview eligible
bookmarks and confirm synchronization as the desktop user with a valid
Kerberos ticket. Use the same page to recover an interrupted bookmark
transaction or restore the latest managed checkpoint. To remove one share,
edit and redeploy the policy then review synchronization, preserving the
existing ordinary personal entries. After verifying a completed sync, use Accept managed
bookmarks to archive its checkpoint and permit the next policy sync. Kerberos service
access depends on the desktop SMB backend. Qualify the actual authentication
mechanism independently. Login integration remains opt-in; live Kerberos SMB
acceptance is pending.

## Printing

Discover the local queues and save multiple private IPP/IPPS driverless
definitions in the Control Center. See the [synthetic printer definitions](../templates/printers.example.json). Choose names prefixed with `oe-` and at
most one default. `operational cups-create` reads a reviewed definition
document from standard input. `cups-update` reads fields `name`, `before`
and `after` with old and new IPP/IPPS URIs. The ownership receipt, endpoint
and pending job checks must pass. `cups-undo-update` uses the same fields
with endpoints reversed and only allows the last managed update. The
rollback for created queues uses `cups-rollback`. These installed admin
commands review plans. Mutation requires separate qualification and exclusive
administration. A pending receipt calls for manual reconciliation of the
queue, job, marker, endpoint and default state before retrying.
For endpoint updates, `cups-recover-update` reviews whether the endpoint
remained unchanged or reached its target. With separate qualification and
a fresh approval it reconciles only the receipt.

## Windows workspace

Use the Windows VM form for a digest-pinned Dockur image, edition, dedicated
storage and capacity. Review KVM, TUN and filesystem support. A qualified
administrator must separately approve the image and properly licensed
installation media. The default is manual startup with networking disabled.
The separate loopback design binds only IPv4 localhost and requires a
dedicated internal Docker bridge, reviewed offline media, Docker Engine 28
or newer, and proven isolation. FreeRDP needs the certificate DNS identity,
a trusted guest certificate, strict verification and NLA. Review a full
managed container ID for start/stop diagnostics. Preserve guest storage and
reconcile interrupted operations with the runtime. Lifecycle and loopback
connection remain gated. Native Windows guest enrollment is separately
authorized. Inbound RDP to the Linux workstation remains OFF.

## Enterprise Guard, backup and recovery

Enterprise Guard checks the managed configuration baseline. Review the
[example Pacman hook](../templates/90-omarchy-enterprise-guard.hook.example)
and its managed scope before adopting it. Preserve the current baseline and
review drift before refreshing it. Keep independent local administrator access
and follow the [filesystem and backup guidance](installation.md#filesystems-and-recovery).
After an interruption, inspect the journal for the affected workflow and
review its recovery plan before issuing a new approval. See
[troubleshooting](troubleshooting.md) for common symptoms.
