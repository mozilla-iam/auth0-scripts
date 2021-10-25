# DEPRECATION NOTICE

*This repo is deprecated and all scripts within it have been migrated either to other repositories or to IT puppet.*

# auth0-scripts
Scripts to manage auth0 via API

It also includes other IAM related scripts, such as DuoSecurity scripts that may be useful in combination with IAM or Auth0.

# Scripts

## DuoSecurity

This repo was a former home of scripts to manage Duo users based on LDAP values:
### duo_assign_groups.py
Automatically assign group to new users in Duo. This is used as a default Duo group for all users as Duo cannot do this
automatically.

### duo_client_purge.py
Deprovision users when they leave (disappear in LDAP)

These were transitioned into IT puppet, where they are now maintained.  This was done without realizing that there was a github repo that otherwise had them.

The scripts have diverged greatly.  Since there is little need for this repo, and it stands on the verge of being obsoleted when #58 lands.

The contents can be found at `ssh://gitolite3@git-internal.mozilla.org/sysadmins/puppet.git` as of commit `c14aec229af5dd230a8a4667339d3dde06ca9c8e`
```
modules/ldap_crons/manifests/duo_client_purge.pp
modules/ldap_crons/files/duo_client_purge/duo_client_purge.py
modules/ldap_crons/templates/duo_client_purge/duo_client_purge_settings.json.erb
modules/ldap_crons/manifests/duo_assign_groups.pp
modules/ldap_crons/files/duo_assign_groups/duo_assign_groups.py
modules/ldap_crons/templates/duo_assign_groups/duo_assign_groups_settings.json.erb
```

## LDAP
### disable_deactivated_accounts.py
Automatically set Auth0 'ad' (LDAP) accounts to blocked ('disabled') if they are disabled in LDAP.

### ldap2s3
Removed decommissioned ldap2s3; replaced by `ldap_to_cis` in IAM-858.

### clearpass_disable_accounts.py
Automatically deletes users in Clearpass API (wifi) if they are disabled in LDAP or not part of the right group.
