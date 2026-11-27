# File servers and Nautilus

Use the [synthetic SMB policy](../templates/file-servers.example.json) to
review friendly share names and optional group rules. After an administrator
reviews and deploys approved policy on a qualified system, preview eligible
Nautilus bookmarks in File Servers. Review the policy and keep your personal
bookmarks before confirming synchronization as the desktop user.

Verify the actual SMB authentication mechanism with the desktop backend.
A valid Kerberos ticket and correctly configured GVFS SMB support are part
of live qualification. Use Recover or Restore for interrupted or unwanted
managed changes, then accept a verified checkpoint before a new sync.
See [managed bookmark administration](administration.md#file-servers-and-nautilus).
