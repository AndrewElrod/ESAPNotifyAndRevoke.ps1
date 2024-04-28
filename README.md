# ESAPNotifyAndRevoke.ps1
Detect workstations configured for elevated rights, revoke if expired, and notify to renew if expiration is coming up.

Companion to AddManagedByToLocalAdmin.ps1

Needs to be run with a service account that has permissions to write to ManagedBy and AccountExpirationDate on workstation objects.

Expiration date should be set to the day after expiration to make sure that the object doesn't actually expire.
