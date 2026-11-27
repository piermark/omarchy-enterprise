# Active Directory

Use the [Control Center](control-center.md) Active Directory page to review
draft configuration. For a synthetic review use DNS domain `ad.example.com`,
Kerberos realm `AD.EXAMPLE.COM`, and a fictional workstation. Compare the
generated Samba, SSSD and Kerberos settings with the intended design.

- Samba ADS handles the machine account and trust relationship.
- SSSD resolves directory accounts and groups through NSS and can participate
  in authentication and access control through PAM.
- Kerberos provides tickets for compatible services. A live evaluation needs
  working AD DNS discovery, synchronized time, matching realms and valid
  credentials. A ticket by itself does not establish that an SMB client uses it.

Review SDDM separately. Keep domain login disabled during source evaluation
and retain a working local administrator login. Enrollment, live identity
resolution, PAM and graphical login require separate qualification. Review
[administration](administration.md#active-directory-sssd-and-graphical-login)
for diagnostics and ownership checks.
