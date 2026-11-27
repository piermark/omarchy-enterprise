# Updates, backup and recovery

Keep an independently restorable backup and a working local administrator
login. Btrfs snapshots can help you roll back covered subvolumes. Check
whether home, separate mounts and Windows guest disks need separate backups
and test restoration before relying on snapshots.

Before an update, review Guard baseline drift, pending receipts and the
previous trusted package. After a failed or interrupted update, inspect
Pacman's transaction and the affected workflow journal before retrying.
Generate a fresh recovery or rollback plan, compare its ownership scope
with what actually changed, then approve only that operation.

For bookmark or CUPS recovery, preserve the latest checkpoint or receipt and
reconcile current state first. For Standalone staging, review removal with
`./uninstall.sh --root "$stage"` in the original terminal.
See [administrator workflows](administration.md) and
[troubleshooting](troubleshooting.md).
